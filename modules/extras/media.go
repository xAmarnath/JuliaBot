package extras

import (
	"context"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/xAmarnath/gogram/telegram"
	modules "main/modules"
)

type MirrorOptions struct {
	Destination   any
	NoProgress    bool
	ForceDocument bool
	NoThumb       bool
	Delay         int
	FileName      string
	SourceLink    string
}

func parseMirrorArgs(args string) *MirrorOptions {
	opts := &MirrorOptions{}
	parts := strings.Fields(args)

	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "-c":
			if i+1 < len(parts) {
				i++
				dest := parts[i]
				if strings.HasPrefix(dest, "@") {
					opts.Destination = dest[1:]
				} else if strings.Contains(dest, "t.me/c/") {
					reg := regexp.MustCompile(`t.me/c/(\d+)`)
					match := reg.FindStringSubmatch(dest)
					if len(match) == 2 {
						chatID, _ := strconv.ParseInt("-100"+match[1], 10, 64)
						opts.Destination = chatID
					}
				} else if strings.Contains(dest, "t.me/") {
					reg := regexp.MustCompile(`t.me/(\w+)`)
					match := reg.FindStringSubmatch(dest)
					if len(match) == 2 {
						opts.Destination = match[1]
					}
				} else {
					if id, err := strconv.ParseInt(dest, 10, 64); err == nil {
						opts.Destination = id
					} else {
						opts.Destination = dest
					}
				}
			}
		case "-nop":
			opts.NoProgress = true
		case "-doc":
			opts.ForceDocument = true
		case "-not":
			opts.NoThumb = true
		case "-d":
			if i+1 < len(parts) {
				i++
				opts.Delay, _ = strconv.Atoi(parts[i])
			}
		case "-fn":
			if i+1 < len(parts) {
				i++
				opts.FileName = parts[i]
			}
		default:
			if strings.Contains(parts[i], "t.me/") {
				opts.SourceLink = parts[i]
			} else if opts.FileName == "" && !strings.HasPrefix(parts[i], "-") {
				opts.FileName = parts[i]
			}
		}
	}

	return opts
}

// media utilities

func convertThumb(thumbFilePath string, width int) string {
	// use ffmpeg, keep aspect ratio
	// ffmpeg -i thumb.jpg -vf scale=512:-1 thumb_512.jpg

	cmd := exec.Command("ffmpeg", "-i", thumbFilePath, "-vf", fmt.Sprintf("scale=%d:-1", width), strings.Replace(thumbFilePath, ".jpg", fmt.Sprintf("_%d.jpg", width), 1))
	err := cmd.Run()
	if err != nil {
		return ""
	}

	return strings.Replace(thumbFilePath, ".jpg", fmt.Sprintf("_%d.jpg", width), 1)
}

func SetThumbHandler(m *telegram.NewMessage) error {
	if !m.IsReply() {
		m.Reply("Error: Reply to a media message")
		return nil
	}

	msg, err := m.GetReplyMessage()
	if err != nil {
		m.Reply("Error: " + err.Error())
		return nil
	}

	if msg.Photo() == nil && msg.Sticker() == nil {
		m.Reply("Error: Not a photo or sticker")
		return nil
	}

	_, err = modules.TransferDownload(msg, &telegram.DownloadOptions{FileName: "thumb.jpg"})
	if err != nil {
		m.Reply("Error: " + err.Error())
		return nil
	}

	m.Reply("Thumbnail set successfully!!")

	if m.Args() != "" {
		width := m.Args()
		wid, _ := strconv.Atoi(width)
		if wid < 1 {
			m.Reply("Error: Invalid width")
			return nil
		}
		thumb := convertThumb("thumb.jpg", wid)
		if thumb == "" {
			m.Reply("Error: Failed to convert thumbnail")
			return nil
		}

		os.Remove("thumb.jpg")
		os.Rename(thumb, "thumb.jpg")
	}
	return nil
}

func MirrorFileHandler(m *telegram.NewMessage) error {
	opts := parseMirrorArgs(m.Args())
	source := *m
	if !m.IsReply() {
		message := *m.Message
		message.Message = "/ldl " + opts.SourceLink
		source.Message = &message
	}
	r, _, err := modules.ResolveDownloadSource(&source)
	if err != nil {
		_, err = m.Reply("Cannot read source: " + html.EscapeString(err.Error()))
		return err
	}
	if r == nil || r.File == nil {
		_, err = m.Reply("Reply to a file or provide a t.me file link.")
		return err
	}
	status, err := m.Reply("Downloading…")
	if err != nil {
		return err
	}
	ctx, done := modules.TrackUserFileTransfer(status, m.SenderID())
	defer done()
	if err = os.MkdirAll("downloads", 0755); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("downloads", "mirror-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	name := opts.FileName
	if name == "" {
		name = r.File.Name
	}
	name = filepath.Base(name)
	if name == "." || name == "/" {
		name = "file"
	}
	dl := &telegram.DownloadOptions{Ctx: ctx, FileName: filepath.Join(dir, name)}
	if !opts.NoProgress {
		dl.ProgressManager = modules.TransferProgress(status, modules.TransferMediaDC(r.Media()))
	}
	fi, err := modules.TransferDownload(r, dl)
	if err == nil {
		upload := &telegram.UploadOptions{Ctx: ctx}
		if !opts.NoProgress {
			upload.ProgressManager = modules.TransferProgress(status)
		}
		media := &telegram.MediaOptions{ForceDocument: opts.ForceDocument, Spoiler: true, Upload: upload, Caption: html.EscapeString(name), ParseMode: telegram.HTML}
		if !opts.NoThumb {
			if _, e := os.Stat("thumb.jpg"); e == nil {
				media.Thumb = "thumb.jpg"
			}
		}
		if opts.Destination == nil {
			_, err = modules.TransferUploadEdit(status, fi, media)
		} else {
			_, err = modules.TransferSendMedia(m.Client, opts.Destination, fi, media)
			if err == nil {
				_, err = status.Edit("File mirrored successfully.")
			}
		}
	}
	if err != nil {
		text := "Mirror failed: " + html.EscapeString(err.Error())
		if errors.Is(err, context.Canceled) {
			text = "Mirror cancelled. Partial files removed."
		}
		_, editErr := status.Edit(text, &telegram.SendOptions{ParseMode: telegram.HTML})
		return editErr
	}
	return nil
}
func registerMediaHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:thumb", SetThumbHandler, telegram.CustomFilter(modules.FilterTransferUser))
	modules.OnCommand(c, "cmd:mirror", MirrorFileHandler, telegram.CustomFilter(modules.FilterTransferUser))
}

func init() {
	modules.QueueHandlerRegistration(registerMediaHandlers)
}
