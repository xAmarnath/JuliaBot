package modules

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
)

var splitSizePattern = regexp.MustCompile(`(?i)^([0-9]+(?:\.[0-9]+)?)\s*(B|KB|MB|GB|KIB|MIB|GIB)?$`)

func parseSplitSize(text string) (int64, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, nil
	}
	m := splitSizePattern.FindStringSubmatch(text)
	if m == nil {
		return 0, errors.New("invalid split size; use a value such as 1900MiB or 3GiB")
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, err
	}
	mult := map[string]float64{"": 1, "B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9, "KIB": 1024, "MIB": 1024 * 1024, "GIB": 1024 * 1024 * 1024}[strings.ToUpper(m[2])]
	n *= mult
	if math.IsNaN(n) || math.IsInf(n, 0) || n < 1 || n >= float64(math.MaxInt64) {
		return 0, errors.New("split size is out of range")
	}
	return int64(n), nil
}

func uploadArguments(raw string) (string, bool, bool, int64, error) {
	parts := strings.Fields(raw)
	var kept []string
	sizeText := os.Getenv("UPLOAD_SPLIT_SIZE")
	for i := 0; i < len(parts); i++ {
		if parts[i] == "--split" || parts[i] == "--split-size" {
			if i+1 >= len(parts) {
				return "", false, false, 0, errors.New("provide a size after --split")
			}
			i++
			sizeText = parts[i]
		} else {
			kept = append(kept, parts[i])
		}
	}
	name, spoiler, document := parseUploadArguments(strings.Join(kept, " "))
	size, err := parseSplitSize(sizeText)
	return name, spoiler, document, size, err
}

func uploadPartSize(size, limit, requested int64) (int64, int64, error) {
	if size <= 0 || limit <= 0 {
		return 0, 0, errors.New("file size and account limit must be positive")
	}
	part := limit
	if requested > 0 {
		part = min(requested, limit)
	}
	count := 1 + (size-1)/part
	if count > 10000 {
		return 0, 0, errors.New("split size would create over 10,000 parts; choose a larger size")
	}
	return part, count, nil
}

func uploadAccountLimits(ctx context.Context, bot *tg.Client) (tg.UploadLimits, error) {
	if s := transferForContext(bot, ctx); s != nil {
		if user, ok := s.user.(*tg.Client); ok {
			return user.GetUploadLimits(ctx)
		}
	}
	return bot.GetUploadLimits(ctx)
}

func TransferUploadLimits(ctx context.Context, bot *tg.Client) (tg.UploadLimits, error) {
	return uploadAccountLimits(ctx, bot)
}

func bindTransferStatus(controller, status *tg.NewMessage) func() {
	key := fileTransferKey{status.ChatID(), status.ID}
	cancelMutex.Lock()
	active, ok := downloadCancels[fileTransferKey{controller.ChatID(), controller.ID}]
	if ok {
		downloadCancels[key] = active
	}
	cancelMutex.Unlock()
	return func() { cancelMutex.Lock(); delete(downloadCancels, key); cancelMutex.Unlock() }
}

func UploadHandle(m *tg.NewMessage) error {
	filename, spoiler, document, requested, err := uploadArguments(m.Args())
	if err != nil {
		_, err = m.Reply(html.EscapeString(err.Error()))
		return err
	}
	if filename == "" {
		_, err = m.Reply("Usage: <code>/ul filename [-s] [--doc] [--split 1900MiB]</code>")
		return err
	}
	file, err := os.Open(filename)
	if err != nil {
		_, err = m.Reply("Cannot open file: " + html.EscapeString(err.Error()))
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() || info.Size() == 0 {
		_, err = m.Reply("Choose a non-empty file.")
		return err
	}
	status, err := transferMessageCall(context.Background(), func() (*tg.NewMessage, error) { return m.Reply("Preparing upload…") })
	if err != nil {
		return err
	}
	ctx, done := TrackUserFileTransfer(status, m.SenderID())
	defer done()
	started := time.Now()
	limits, err := uploadAccountLimits(ctx, m.Client)
	if err != nil {
		return uploadFailure(status, err)
	}
	partSize, count, err := uploadPartSize(info.Size(), limits.MaxFileSize, requested)
	if err != nil {
		return uploadFailure(status, err)
	}
	for i := int64(0); i < count; i++ {
		if err := ctx.Err(); err != nil {
			return uploadFailure(status, err)
		}
		partStatus := status
		name := filepath.Base(filename)
		var media any = filename
		unbind := func() {}
		if count > 1 {
			name = fmt.Sprintf("%s.part%05d", name, i+1)
			partStatus, err = transferMessageCall(ctx, func() (*tg.NewMessage, error) {
				return m.Reply(fmt.Sprintf("Uploading part %d/%d…", i+1, count))
			})
			if err != nil {
				return uploadFailure(status, fmt.Errorf("prepare part %d/%d: %w", i+1, count, err))
			}
			unbind = bindTransferStatus(status, partStatus)
			n := min(partSize, info.Size()-i*partSize)
			media = tg.ReaderAtSource{Reader: io.NewSectionReader(file, i*partSize, n), Size: n, Name: name}
		}
		partStarted := time.Now()
		var uploaded *tg.NewMessage
		uploaded, err = TransferUploadEdit(partStatus, media, &tg.MediaOptions{FileName: name, ForceDocument: document || count > 1,
			Spoiler: spoiler, Caption: transferCaption(name), ParseMode: tg.HTML,
			Upload: &tg.UploadOptions{Ctx: ctx, ProgressManager: TransferProgress(partStatus)}})
		unbind()
		if err != nil {
			if partStatus != status {
				_ = uploadFailure(partStatus, err)
			}
			return uploadFailure(status, err)
		}
		caption := uploadCompletedCaption(name, time.Since(partStarted))
		// Stickers have no editable caption; delivery already completed.
		if uploaded.Sticker() == nil {
			if _, captionErr := transferMessageCall(ctx, func() (*tg.NewMessage, error) {
				return uploaded.Edit(caption, &tg.SendOptions{ParseMode: tg.HTML})
			}); captionErr != nil {
				m.Client.Log.Warn("upload completed but timing caption failed: %v", captionErr)
			}
		}
		if count > 1 {
			_, _ = transferMessageCall(ctx, func() (*tg.NewMessage, error) {
				return status.Edit(fmt.Sprintf("Uploaded %d/%d parts of %s", i+1, count, transferCaption(filename)), &tg.SendOptions{ReplyMarkup: transferCancelKeyboard(status.ID)})
			})
		}
	}
	if count > 1 {
		_, err = transferMessageCall(ctx, func() (*tg.NewMessage, error) {
			return status.Edit(fmt.Sprintf("Uploaded all %d parts of %s in %.2f seconds.\nJoin them in order with <code>cat %s.part* &gt; %s</code>.", count, transferCaption(filename), time.Since(started).Seconds(), html.EscapeString(shellQuote(filepath.Base(filename))), html.EscapeString(shellQuote(filepath.Base(filename)))))
		})
	}
	return err
}

func uploadCompletedCaption(name string, elapsed time.Duration) string {
	return fmt.Sprintf("%s\nUploaded in <b>%.2f seconds</b>.", transferCaption(name), elapsed.Seconds())
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func uploadFailure(status *tg.NewMessage, err error) error {
	status.Client.Log.Error("upload stopped: %v", err)
	text := "Upload failed: " + html.EscapeString(err.Error())
	if errors.Is(err, context.Canceled) {
		text = "Upload cancelled. Completed parts remain available."
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, editErr := transferMessageCall(ctx, func() (*tg.NewMessage, error) {
		return status.Edit(text, &tg.SendOptions{ParseMode: tg.HTML})
	})
	if editErr != nil {
		_, sendErr := transferMessageCall(ctx, func() (*tg.NewMessage, error) { return status.Reply(text) })
		return errors.Join(err, editErr, sendErr)
	}
	return nil
}
