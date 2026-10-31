package extras

import (
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tg "github.com/xAmarnath/gogram/telegram"
)

func TestKangPhotoAndImageSources(t *testing.T) {
	for _, media := range []tg.MessageMedia{&tg.MessageMediaPhoto{Photo: &tg.PhotoObj{}}, &tg.MessageMediaDocument{Document: &tg.DocumentObj{MimeType: "image/jpeg"}}} {
		s, e := kangDetectSource(&tg.NewMessage{Message: &tg.MessageObj{Media: media}})
		if e != nil || s.Kind != "normal" || s.Media != media {
			t.Fatal(s, e)
		}
	}
	if _, e := kangDetectSource(&tg.NewMessage{Message: &tg.MessageObj{Media: &tg.MessageMediaDocument{Document: &tg.DocumentObj{MimeType: "application/pdf"}}}}); e == nil {
		t.Fatal("accepted PDF")
	}
}
func TestKangAspectRatio(t *testing.T) {
	for _, v := range [][4]int{{1000, 500, 512, 256}, {500, 1000, 256, 512}, {100, 100, 512, 512}, {1, 10000, 1, 512}, {512, 400, 512, 400}} {
		w, h, e := kangSize(v[0], v[1])
		if e != nil || w != v[2] || h != v[3] || !kangValidSize(w, h) {
			t.Fatal(v, w, h, e)
		}
	}
	if kangValidSize(512, 0) || kangValidSize(513, 512) || kangValidSize(256, 256) {
		t.Fatal("invalid sticker size accepted")
	}
}
func TestKangImageConversion(t *testing.T) {
	if _, e := exec.LookPath("ffmpeg"); e != nil {
		t.Skip("ffmpeg unavailable")
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "wide.png"), filepath.Join(dir, "sticker.webp")
	im := image.NewNRGBA(image.Rect(0, 0, 800, 400))
	im.Set(400, 200, color.NRGBA{R: 255, A: 255})
	f, e := os.Create(input)
	if e != nil {
		t.Fatal(e)
	}
	e = png.Encode(f, im)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if e = kangEncodeImage(input, output); e != nil {
		t.Fatal(e)
	}
	f, e = os.Open(output)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	got, _, e := image.Decode(f)
	if e != nil {
		t.Fatal(e)
	}
	if got.Bounds().Dx() != 512 || got.Bounds().Dy() != 256 {
		t.Fatal(got.Bounds())
	}
	_, _, _, a := got.At(0, 0).RGBA()
	if a != 0 {
		t.Fatal("transparency lost", a)
	}
}
func TestKangPackNameCollision(t *testing.T) {
	var names []string
	_, name, e := kangCreatePack(func(n string) (tg.MessagesStickerSet, error) {
		names = append(names, n)
		if len(names) < 3 {
			return nil, errors.New("SHORT_NAME_OCCUPIED")
		}
		return &tg.MessagesStickerSetObj{}, nil
	}, 123456789, "normal", 1, "JuliaTestBot")
	if e != nil || len(names) != 3 || !strings.HasPrefix(name, "v4_") || !strings.HasSuffix(name, "_by_JuliaTestBot") {
		t.Fatal(names, name, e)
	}
	n := 0
	want := errors.New("USER_IS_BLOCKED")
	_, _, e = kangCreatePack(func(string) (tg.MessagesStickerSet, error) { n++; return nil, want }, 1, "normal", 1, "bot")
	if !errors.Is(e, want) || n != 1 {
		t.Fatal("retried unrelated failure", e, n)
	}
}
