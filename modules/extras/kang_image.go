package extras

import (
	"context"
	"fmt"
	"image"
	_ "image/gif"
	"math"
	"os"
	"os/exec"
	"strconv"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
)

func kangValidSize(w, h int) bool {
	return w > 0 && h > 0 && w <= 512 && h <= 512 && (w == 512 || h == 512)
}
func kangDocumentSized(d *tg.DocumentObj) bool {
	if d == nil {
		return false
	}
	for _, attr := range d.Attributes {
		if a, ok := attr.(*tg.DocumentAttributeImageSize); ok {
			return kangValidSize(int(a.W), int(a.H))
		}
	}
	return false
}
func kangSize(w, h int) (int, int, error) {
	if w <= 0 || h <= 0 {
		return 0, 0, fmt.Errorf("invalid image dimensions")
	}
	if w >= h {
		return 512, max(1, int(math.Round(float64(h)*512/float64(w)))), nil
	}
	return max(1, int(math.Round(float64(w)*512/float64(h)))), 512, nil
}
func kangEncodeImage(input, output string) error {
	f, e := os.Open(input)
	if e != nil {
		return e
	}
	cfg, _, e := image.DecodeConfig(f)
	f.Close()
	if e != nil {
		return fmt.Errorf("read image dimensions: %w", e)
	}
	w, h, e := kangSize(cfg.Width, cfg.Height)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, quality := range []string{"80", "60", "40"} {
		args := []string{"-nostdin", "-v", "error", "-y", "-i", input, "-frames:v", "1", "-vf", fmt.Sprintf("scale=%d:%d:flags=lanczos,setsar=1", w, h), "-c:v", "libwebp", "-pix_fmt", "bgra", "-q:v", quality, "-compression_level", "6", "-an", "-sn", output}
		if b, e := exec.CommandContext(ctx, "ffmpeg", args...).CombinedOutput(); e != nil {
			return fmt.Errorf("image conversion failed: %w: %.500s", e, b)
		}
		info, e := os.Stat(output)
		if e != nil {
			return e
		}
		if info.Size() > 512*1024 {
			continue
		}
		f, e = os.Open(output)
		if e != nil {
			return e
		}
		got, _, e := image.DecodeConfig(f)
		f.Close()
		if e != nil {
			return e
		}
		if !kangValidSize(got.Width, got.Height) {
			return fmt.Errorf("converted sticker dimensions invalid")
		}
		return nil
	}
	return fmt.Errorf("image could not be compressed under Telegram's 512 KiB sticker limit")
}
func kangPackName(userID int64, kind string, number, version int, bot string) string {
	code := map[string]string{"normal": "s", "webm": "v", "tgs": "a"}[kind]
	if code == "" {
		code = "s"
	}
	return fmt.Sprintf("v%d_%s_%s_%s_by_%s", version, strconv.FormatInt(userID, 36), code, strconv.FormatInt(int64(number), 36), bot)
}
func kangCreatePack(create func(string) (tg.MessagesStickerSet, error), userID int64, kind string, number int, bot string) (tg.MessagesStickerSet, string, error) {
	var last error
	for version := 2; version < 22; version++ {
		name := kangPackName(userID, kind, number, version, bot)
		result, err := create(name)
		if err == nil {
			return result, name, nil
		}
		if !tg.MatchError(err, "SHORT_NAME_OCCUPIED") {
			return nil, "", err
		}
		last = err
	}
	return nil, "", last
}
