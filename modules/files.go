package modules

import (
	"context"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
)

type fileTransferKey struct {
	chat    int64
	message int32
}

type activeFileTransfer struct {
	ctx    context.Context
	cancel context.CancelFunc
	owner  int64
}

var (
	downloadCancels = make(map[fileTransferKey]activeFileTransfer)
	downloadPaths   = make(map[string]bool)
	cancelMutex     sync.RWMutex
)

func TrackFileTransfer(m *tg.NewMessage, owner int64) (context.Context, func()) {
	return trackFileTransfer(context.Background(), m, owner)
}

// TrackUserFileTransfer opts explicit download/upload commands into the relay.
func TrackUserFileTransfer(m *tg.NewMessage, owner int64) (context.Context, func()) {
	return trackFileTransfer(WithTransferAccount(context.Background()), m, owner)
}

// UpdateFileTransferStatus preserves the cancel control during long jobs.
func UpdateFileTransferStatus(m *tg.NewMessage, text string) {
	_, _ = m.Edit(text, &tg.SendOptions{ParseMode: tg.HTML, ReplyMarkup: transferCancelKeyboard(m.ID)})
}

func trackFileTransfer(parent context.Context, m *tg.NewMessage, owner int64) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	key := fileTransferKey{m.ChatID(), m.ID}
	cancelMutex.Lock()
	downloadCancels[key] = activeFileTransfer{ctx, cancel, owner}
	cancelMutex.Unlock()
	_, _ = m.Edit(m.MessageText(), &tg.SendOptions{ParseMode: tg.HTML, ReplyMarkup: transferCancelKeyboard(m.ID)})
	return ctx, func() { cancel(); cancelMutex.Lock(); delete(downloadCancels, key); cancelMutex.Unlock() }
}
func SendFileByIDHandle(m *tg.NewMessage) error {
	fileId := m.Args()
	if fileId == "" {
		m.Reply("No fileId provided")
		return nil
	}

	file, err := tg.ResolveBotFileID(fileId)
	if err != nil {
		m.Reply("Error: " + err.Error())
		return nil
	}

	TransferReplyMedia(m, file)
	return nil
}

func GetFileIDHandle(m *tg.NewMessage) error {
	if !m.IsReply() {
		m.Reply("Reply to a file to get its fileId")
		return nil
	}

	r, err := m.GetReplyMessage()
	if err != nil {
		m.Reply("Error: " + err.Error())
		return nil
	}

	if r.File == nil {
		m.Reply("No file found in the reply")
		return nil
	}

	m.Reply("<b>FileId:</b> <code>" + r.File.FileID + "</code>")
	return nil
}

func parseUploadArguments(raw string) (string, bool, bool) {
	var parts []string
	spoiler, document := false, false
	for _, part := range strings.Fields(raw) {
		switch part {
		case "-s":
			spoiler = true
		case "--doc", "-doc":
			document = true
		default:
			parts = append(parts, part)
		}
	}
	return strings.Trim(strings.Join(parts, " "), "\""), spoiler, document
}

var downloadLink = regexp.MustCompile(`^(?:https?://)?(?:www\.)?t\.me/(?:(c)/)?([A-Za-z0-9_]+)/([0-9]+)(?:\?[^\s]*)?$`)

func ResolveDownloadSource(m *tg.NewMessage) (*tg.NewMessage, string, error) {
	if m.IsReply() {
		r, err := m.GetReplyMessage()
		return r, strings.TrimSpace(m.Args()), err
	}
	match := downloadLink.FindStringSubmatch(strings.TrimSpace(m.Args()))
	if match == nil {
		return nil, "", errors.New("reply to a file or provide a valid t.me message link")
	}
	id, err := strconv.ParseInt(match[3], 10, 32)
	if err != nil || id <= 0 {
		return nil, "", errors.New("invalid message ID")
	}
	var peer any = match[2]
	if match[1] == "c" {
		chat, err := strconv.ParseInt(match[2], 10, 64)
		if err != nil || chat <= 0 {
			return nil, "", errors.New("invalid channel ID")
		}
		peer = chat
	}
	r, err := m.Client.GetMessageByID(peer, int32(id))
	return r, "", err
}

func DownloadHandle(m *tg.NewMessage) error {
	r, name, err := ResolveDownloadSource(m)
	if err != nil {
		_, err = m.Reply(html.EscapeString(err.Error()))
		return err
	}
	if r == nil || r.File == nil {
		_, err = m.Reply("Not a file.")
		return err
	}
	if name == "" {
		name = r.File.Name
	}
	name = filepath.Base(name)
	if name == "." || name == string(filepath.Separator) || name == "" {
		_, err = m.Reply("Invalid filename.")
		return err
	}
	if err = os.MkdirAll("downloads", 0755); err != nil {
		return err
	}
	path := filepath.Join("downloads", name)
	cancelMutex.Lock()
	busy := downloadPaths[path]
	if !busy {
		downloadPaths[path] = true
	}
	cancelMutex.Unlock()
	if busy {
		_, err = m.Reply("This file is already being downloaded.")
		return err
	}
	defer func() { cancelMutex.Lock(); delete(downloadPaths, path); cancelMutex.Unlock() }()
	if _, err = os.Stat(path); err == nil {
		_, err = m.Reply("File already exists: " + transferCaption(path))
		return err
	} else if !os.IsNotExist(err) {
		return err
	}
	status, err := m.Reply("Downloading...")
	if err != nil {
		return err
	}
	ctx, done := TrackUserFileTransfer(status, m.SenderID())
	defer done()
	start := time.Now()
	opt := &tg.DownloadOptions{Ctx: ctx, FileName: path, ProgressManager: TransferProgress(status, TransferMediaDC(r.Media()))}
	file, err := TransferDownload(r, opt)
	if err != nil {
		_ = os.Remove(path)
		message := "Download failed: " + html.EscapeString(err.Error())
		if errors.Is(err, context.Canceled) {
			message = "Download cancelled."
		}
		_, editErr := status.Edit(message)
		return editErr
	}
	_, err = status.Edit(fmt.Sprintf("Downloaded %s in <code>%s</code>", transferCaption(file), time.Since(start).Round(time.Millisecond)))
	return err
}

func CancelDownloadHandle(m *tg.NewMessage) error {
	if !m.IsReply() {
		_, err := m.Reply("Reply to an upload or download progress message to cancel it.")
		return err
	}
	reply, err := m.GetReplyMessage()
	if err != nil {
		return err
	}
	if reply == nil {
		return errors.New("missing transfer message")
	}
	cancelMutex.RLock()
	active, exists := downloadCancels[fileTransferKey{m.ChatID(), reply.ID}]
	cancelMutex.RUnlock()
	if !exists {
		_, err = m.Reply("No active transfer found for this message.")
		return err
	}
	if active.owner != m.SenderID() && m.SenderID() != OwnerId {
		_, err = m.Reply("You cannot cancel this transfer.")
		return err
	}
	active.cancel()
	_, err = m.Reply("Cancellation requested.")
	return err
}

func transferCancelKeyboard(id int32) *tg.ReplyInlineMarkup {
	return tg.NewKeyboard().AddRow(tg.Button.Data("Cancel", fmt.Sprintf("filecancel:%d", id))).Build()
}

func CancelTransferCallback(q *tg.CallbackQuery) error {
	id, err := strconv.ParseInt(strings.TrimPrefix(q.DataString(), "filecancel:"), 10, 32)
	if err != nil || int32(id) != q.MessageID {
		_, err = q.Answer("Invalid transfer.")
		return err
	}
	cancelMutex.RLock()
	active, exists := downloadCancels[fileTransferKey{q.ChatID, q.MessageID}]
	cancelMutex.RUnlock()
	if !exists {
		_, err = q.Answer("This transfer has already finished.")
		return err
	}
	if q.SenderID != active.owner && q.SenderID != OwnerId {
		_, err = q.Answer("Only the sender or bot owner can cancel this transfer.")
		return err
	}
	active.cancel()
	_, _ = q.Answer("Cancelling…")
	_, err = q.Edit("Cancelling…", &tg.SendOptions{})
	return err
}
func FileInfoHandle(m *tg.NewMessage) error {
	if !m.IsReply() {
		m.Reply("Reply to a file to get its info")
		return nil
	}

	r, err := m.GetReplyMessage()
	if err != nil {
		m.Reply("Error: " + err.Error())
		return nil
	}

	var fi struct {
		FileName   string
		Type       string
		Size       int64
		FileID     string
		Attributes map[string]string
	}
	fi.Attributes = make(map[string]string)

	if r.File != nil {
		fi.FileName = r.File.Name
		fi.Size = r.File.Size
		fi.FileID = r.File.FileID
	}

	switch m := r.Message.Media.(type) {
	case *tg.MessageMediaDocument:
		fi.Type = "Document"
		for _, attr := range m.Document.(*tg.DocumentObj).Attributes {
			switch a := attr.(type) {
			case *tg.DocumentAttributeVideo:
				fi.Type = "Video"
				fi.Attributes["Duration"] = strconv.Itoa(int(a.Duration)) + " seconds"
				fi.Attributes["Width"] = strconv.Itoa(int(a.W)) + " px"
				fi.Attributes["Height"] = strconv.Itoa(int(a.H)) + " px"
			case *tg.DocumentAttributeAudio:
				fi.Type = "Audio"
				fi.Attributes["Duration"] = strconv.Itoa(int(a.Duration)) + " seconds"
				fi.Attributes["Title"] = a.Title
				fi.Attributes["Performer"] = a.Performer
				fi.Attributes["Voice"] = strconv.FormatBool(a.Voice)
			case *tg.DocumentAttributeAnimated:
				fi.Type = "Animated"
			case *tg.DocumentAttributeSticker:
				fi.Type = "Sticker"
				fi.Attributes["Alt"] = a.Alt
			}
		}
	case *tg.MessageMediaPhoto:
		fi.Type = "Photo"
	case *tg.MessageMediaPoll:
		fi.Type = "Poll"
	case *tg.MessageMediaGeo:
		fi.Type = "Geo"
		fi.Attributes["AccuracyRadius"] = strconv.Itoa(int(m.Geo.(*tg.GeoPointObj).AccuracyRadius)) + " meters"
		fi.Attributes["Latitude"] = strconv.FormatFloat(m.Geo.(*tg.GeoPointObj).Lat, 'f', 6, 64)
		fi.Attributes["Longitude"] = strconv.FormatFloat(m.Geo.(*tg.GeoPointObj).Long, 'f', 6, 64)
	default:
		fi.Type = "Unknown"
	}

	var output strings.Builder
	output.WriteString("<b>File Information</b>\n")
	output.WriteString("────────────────────\n")
	output.WriteString("<b>FileName</b>: <code>")
	output.WriteString(fi.FileName)
	output.WriteString("</code>\n")
	output.WriteString("<b>Type</b>: <code>")
	output.WriteString(fi.Type)
	output.WriteString("</code>\n")
	output.WriteString("<b>Size</b>: <code>")
	output.WriteString(HumanBytes(uint64(fi.Size)))
	output.WriteString("</code>\n")
	output.WriteString("<b>FileID</b>: <code>")
	output.WriteString(fi.FileID)
	output.WriteString("</code>\n")
	if len(fi.Attributes) > 0 {
		output.WriteString("<b>Attributes</b>:\n")
		for k, v := range fi.Attributes {
			output.WriteString("   • <b>")
			output.WriteString(k)
			output.WriteString("</b>: <code>")
			output.WriteString(v)
			output.WriteString("</code>\n")
		}
	}

	m.Reply(output.String())
	return nil
}

func init() {
	QueueHandlerRegistration(registerFileHandlers)

	Mods.AddModule("Files", `<b>Here are the commands available in Files module:</b>

<code>/file &lt;fileId&gt;</code> - Send a file by its fileId
<code>/fid</code> - Reply to a file to get its fileId
<code>/ul [filename] [-s] [--doc] [--split 1900MiB]</code> - Upload or split a file; omit the filename to browse downloads, newest first
<code>/ldl [t.me link]</code> - Download a file
<code>/ariadl &lt;HTTP URL or magnet&gt;</code> - Download with aria2
<code>/cancel</code> - Reply to a transfer message to cancel it`)
}

func registerFileHandlers() {
	c := Client
	OnCommand(c, "cmd:file", SendFileByIDHandle, tg.CustomFilter(FilterTransferUser))
	OnCommand(c, "cmd:fid", GetFileIDHandle, tg.CustomFilter(FilterTransferUser))
	OnCommand(c, "cmd:ul", UploadHandle, tg.CustomFilter(FilterTransferUser))
	OnCommand(c, "cmd:ldl", DownloadHandle, tg.CustomFilter(FilterTransferUser))
	OnCommand(c, "cmd:cancel", CancelDownloadHandle, tg.CustomFilter(FilterTransferUser))
	c.On("callback:filecancel:", CancelTransferCallback)
	c.On("callback:ulp:", UploadPickerCallback)
	OnCommand(c, "cmd:ariadl", AriaDownloadHandle, tg.CustomFilter(FilterTransferUser))
	OnCommand(c, "cmd:fileinfo", FileInfoHandle, tg.CustomFilter(FilterTransferUser))
	OnCommand(c, "cmd:finfo", FileInfoHandle, tg.CustomFilter(FilterTransferUser))
}
