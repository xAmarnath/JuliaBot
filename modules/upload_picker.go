package modules

import (
	"fmt"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
)

const uploadPickerPageSize = 8
const uploadPickerTTL = 15 * time.Minute

type uploadChoice struct {
	name, path string
	info       os.FileInfo
}

type uploadPicker struct {
	operation         sync.Mutex
	message           *tg.NewMessage
	messageID         int32
	files             []uploadChoice
	spoiler, document bool
	splitSize         int64
	created           time.Time
}

var uploadPickers = struct {
	sync.Mutex
	entries map[string]*uploadPicker
}{entries: make(map[string]*uploadPicker)}

// WalkDir does not follow symlinks. Include nested download files, such as
// aria2 output, and retain a snapshot so page indexes never shift under a user.
func listUploadChoices(root string) ([]uploadChoice, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var files []uploadChoice
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if os.IsNotExist(err) {
			return nil // A transfer may have just cleaned up its file.
		}
		if err != nil {
			return err
		}
		if info.Size() == 0 || strings.HasSuffix(entry.Name(), ".aria2") {
			return nil
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, uploadChoice{filepath.ToSlash(name), path, info})
		return nil
	})
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].info.ModTime().Equal(files[j].info.ModTime()) {
			return files[i].name < files[j].name
		}
		return files[i].info.ModTime().After(files[j].info.ModTime())
	})
	return files, nil
}

func (f uploadChoice) unchanged() bool {
	info, err := os.Lstat(f.path)
	return err == nil && info.Mode().IsRegular() && os.SameFile(f.info, info) &&
		info.Size() == f.info.Size() && info.ModTime().Equal(f.info.ModTime())
}

func uploadPickerPage(e *uploadPicker, token string, page int) (string, *tg.ReplyInlineMarkup, bool) {
	pages := (len(e.files) + uploadPickerPageSize - 1) / uploadPickerPageSize
	if page < 0 || page >= pages {
		return "", nil, false
	}
	kb := tg.NewKeyboard()
	for i := page * uploadPickerPageSize; i < min((page+1)*uploadPickerPageSize, len(e.files)); i++ {
		label := []rune(strings.Join(strings.Fields(e.files[i].name), " "))
		if len(label) > 55 {
			label = append(label[:52], '.', '.', '.')
		}
		kb.AddRow(tg.Button.Data(fmt.Sprintf("%s (%s)", string(label), HumanBytes(uint64(e.files[i].info.Size()))), fmt.Sprintf("ulp:%s:f:%d", token, i)))
	}
	var nav []tg.KeyboardInlineButton
	if page > 0 {
		nav = append(nav, tg.Button.Data("Previous", fmt.Sprintf("ulp:%s:p:%d", token, page-1)))
	}
	if page+1 < pages {
		nav = append(nav, tg.Button.Data("Next", fmt.Sprintf("ulp:%s:p:%d", token, page+1)))
	}
	if len(nav) > 0 {
		kb.AddRow(nav...)
	}
	kb.AddRow(tg.Button.Data("Cancel", "ulp:"+token+":x:0"))
	return fmt.Sprintf("<b>Downloads</b> - newest first\nChoose a file to upload.\nPage %d/%d - %d files", page+1, pages, len(e.files)), kb.Build(), true
}

func dropUploadPicker(token string) {
	uploadPickers.Lock()
	delete(uploadPickers.entries, token)
	uploadPickers.Unlock()
}

func showUploadPicker(m *tg.NewMessage, spoiler, document bool, splitSize int64) error {
	files, err := listUploadChoices("downloads")
	if err != nil {
		_, err = m.Reply("Cannot read downloads: " + html.EscapeString(err.Error()))
		return err
	}
	if len(files) == 0 {
		_, err = m.Reply("No non-empty files in downloads yet. Use /ldl or /ariadl to download a file first.")
		return err
	}
	e := &uploadPicker{message: m, files: files, spoiler: spoiler, document: document, splitSize: splitSize, created: time.Now()}
	token := strings.TrimPrefix(transferToken(), "jb-transfer:")
	e.operation.Lock()
	defer e.operation.Unlock()
	uploadPickers.Lock()
	// Bound abandoned picker snapshots as well as their lifetime.
	if len(uploadPickers.entries) >= 64 {
		oldest, oldestTime := "", time.Now()
		for key, picker := range uploadPickers.entries {
			if picker.created.Before(oldestTime) {
				oldest, oldestTime = key, picker.created
			}
		}
		delete(uploadPickers.entries, oldest)
	}
	uploadPickers.entries[token] = e
	uploadPickers.Unlock()
	time.AfterFunc(uploadPickerTTL, func() { dropUploadPicker(token) })
	text, keyboard, _ := uploadPickerPage(e, token, 0)
	status, err := m.Reply(text, &tg.SendOptions{ParseMode: tg.HTML, ReplyMarkup: keyboard})
	if err != nil {
		dropUploadPicker(token)
		return err
	}
	e.messageID = status.ID
	return nil
}

func (e *uploadPicker) allows(sender, chat int64, messageID int32) bool {
	return sender == e.message.SenderID() && chat == e.message.ChatID() && messageID == e.messageID
}

func UploadPickerCallback(q *tg.CallbackQuery) error {
	answer := func(text string) error { _, err := q.Answer(text); return err }
	parts := strings.Split(q.DataString(), ":")
	if len(parts) != 4 {
		return answer("Invalid selection. Send /ul again.")
	}
	token := parts[1]
	uploadPickers.Lock()
	e := uploadPickers.entries[token]
	uploadPickers.Unlock()
	if e == nil {
		return answer("This list has expired. Send /ul again.")
	}
	if !e.operation.TryLock() {
		return answer("This selection is already being processed.")
	}
	defer e.operation.Unlock()
	if !e.allows(q.SenderID, q.ChatID, q.MessageID) || !IsTransferUser(q.SenderID) {
		return answer("Only the person who requested this list can use it.")
	}
	if CallbackCommandDisabled(q, "ul") {
		return answer("Uploads are disabled in this chat.")
	}
	uploadPickers.Lock()
	current := uploadPickers.entries[token]
	uploadPickers.Unlock()
	if current != e || time.Since(e.created) >= uploadPickerTTL {
		return answer("This list has expired. Send /ul again.")
	}
	index, err := strconv.Atoi(parts[3])
	if err != nil {
		return answer("Invalid selection.")
	}
	switch parts[2] {
	case "p":
		text, keyboard, ok := uploadPickerPage(e, token, index)
		if !ok {
			return answer("That page is unavailable.")
		}
		_ = answer("")
		_, err = q.Edit(text, &tg.SendOptions{ParseMode: tg.HTML, ReplyMarkup: keyboard})
		if err != nil && strings.Contains(err.Error(), "MESSAGE_NOT_MODIFIED") {
			return nil
		}
		return err
	case "x":
		dropUploadPicker(token)
		_ = answer("Cancelled")
		_, err = q.Edit("Upload selection cancelled.")
		return err
	case "f":
		if index < 0 || index >= len(e.files) {
			return answer("That file is unavailable.")
		}
		file := e.files[index]
		if !file.unchanged() {
			return answer("This file changed or was removed. Send /ul for an updated list.")
		}
		dropUploadPicker(token)
		_ = answer("Preparing upload")
		_, _ = q.Edit("Selected: "+html.EscapeString(file.name), &tg.SendOptions{ParseMode: tg.HTML})
		return uploadLocalFile(e.message, file.path, e.spoiler, e.document, e.splitSize)
	default:
		return answer("Invalid selection.")
	}
}
