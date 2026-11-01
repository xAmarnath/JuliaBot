package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tg "github.com/xAmarnath/gogram/telegram"
)

func pickerTestFile(t *testing.T, root, name, content string, modified time.Time) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUploadChoicesNewestFirst(t *testing.T) {
	root := t.TempDir()
	now := time.Now().Truncate(time.Second)
	pickerTestFile(t, root, "old.mp3", "old", now.Add(-time.Hour))
	pickerTestFile(t, root, "album/z.ogg", "new", now)
	pickerTestFile(t, root, "a.mp4", "same time", now)
	pickerTestFile(t, root, "empty", "", now)
	pickerTestFile(t, root, "pending.aria2", "control", now)
	files, err := listUploadChoices(root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range files {
		names = append(names, file.name)
		if !filepath.IsAbs(file.path) || !file.unchanged() {
			t.Fatal("invalid file snapshot", file.path)
		}
	}
	if !reflect.DeepEqual(names, []string{"a.mp4", "album/z.ogg", "old.mp3"}) {
		t.Fatal("wrong sort order or invalid files included", names)
	}
	for _, empty := range []string{t.TempDir(), filepath.Join(root, "missing")} {
		files, err := listUploadChoices(empty)
		if err != nil || len(files) != 0 {
			t.Fatal("empty or missing downloads should be empty", files, err)
		}
	}
}

func TestUploadChoicesDoNotFollowSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	file := pickerTestFile(t, outside, "private.txt", "outside", time.Now())
	if err := os.Symlink(file, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "directory-link")); err != nil {
		t.Fatal(err)
	}
	files, err := listUploadChoices(root)
	if err != nil || len(files) != 0 {
		t.Fatal("followed a symlink", files, err)
	}
}

func TestUploadChoiceRejectsStaleFile(t *testing.T) {
	for _, change := range []string{"removed", "grown", "modified", "replaced"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			now := time.Now().Truncate(time.Second)
			path := pickerTestFile(t, root, "file", "data", now)
			files, err := listUploadChoices(root)
			if err != nil || len(files) != 1 {
				t.Fatal(files, err)
			}
			switch change {
			case "removed":
				err = os.Remove(path)
			case "grown":
				err = os.WriteFile(path, []byte("more data"), 0600)
			case "modified":
				err = os.Chtimes(path, now.Add(time.Minute), now.Add(time.Minute))
			case "replaced":
				err = os.Rename(path, path+".old")
				if err == nil {
					pickerTestFile(t, root, "file", "data", now)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if files[0].unchanged() {
				t.Fatal("accepted stale file", change)
			}
		})
	}
}

func TestUploadPickerPages(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 9; i++ {
		pickerTestFile(t, root, fmt.Sprintf("%02d-%s.ogg", i, strings.Repeat("音", 60)), "audio", time.Now())
	}
	files, err := listUploadChoices(root)
	if err != nil {
		t.Fatal(err)
	}
	e := &uploadPicker{files: files}
	token := strings.Repeat("a", 32)
	for page, count := range []int{8, 1} {
		text, kb, ok := uploadPickerPage(e, token, page)
		if !ok || !strings.Contains(text, fmt.Sprintf("Page %d/2", page+1)) || len(kb.Rows) != count+2 {
			t.Fatal("incorrect page", page, text, kb)
		}
		for i, row := range kb.Rows {
			for _, button := range row.Buttons {
				if !utf8.ValidString(button.Text) || utf8.RuneCountInString(button.Text) > 80 {
					t.Fatal("invalid Unicode label", button.Text)
				}
				callback := string(button.Type.(*tg.InlineButtonTypeCallback).Data)
				if len(callback) > 64 {
					t.Fatal("callback exceeds Telegram limit", callback)
				}
				if i < count && callback != fmt.Sprintf("ulp:%s:f:%d", token, page*8+i) {
					t.Fatal("wrong file selected", callback)
				}
			}
		}
		wantNav := "Next"
		if page == 1 {
			wantNav = "Previous"
		}
		if kb.Rows[count].Buttons[0].Text != wantNav || kb.Rows[count+1].Buttons[0].Text != "Cancel" {
			t.Fatal("incorrect navigation")
		}
	}
	for _, page := range []int{-1, 2, 999999} {
		if _, _, ok := uploadPickerPage(e, token, page); ok {
			t.Fatal("accepted invalid page", page)
		}
	}
}

func TestUploadPickerBindsRequesterAndMessage(t *testing.T) {
	m := relayMessage(123, 5, "/ul", 0)
	m.Message.PeerID = &tg.PeerChat{ChatID: 123}
	m.Message.FromID = &tg.PeerUser{UserID: 456}
	e := &uploadPicker{message: m, messageID: 6}
	if !e.allows(456, 123, 6) {
		t.Fatal("requester rejected")
	}
	for _, values := range [][3]int64{{999, 123, 6}, {456, 999, 6}, {456, 123, 999}} {
		if e.allows(values[0], values[1], int32(values[2])) {
			t.Fatal("accepted wrong requester, chat or message", values)
		}
	}
}
