package extras

import (
	"image/png"
	"os"
	"strings"
	"testing"

	qrcode "github.com/skip2/go-qrcode"
)

func TestQRArtIsScannable(t *testing.T) {
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir("modules/extras")
	texts := []string{"https://github.com/xAmarnath/gogram", "hello", strings.Repeat("JuliaBot ", 40), "தமிழ் 🎉 unicode"}
	for pi, pal := range qrArtPalettes {
		for ti, text := range texts {
			img, err := renderQRArt(text, pal)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			got, err := decodeQRImage(img)
			if err != nil || got != text {
				t.Fatalf("palette %d text %d not scannable: %q %v", pi, ti, got, err)
			}
			if pi == 0 && ti == 0 || pi == 2 && ti == 1 {
				f, _ := os.Create(os.TempDir() + "/qrart_sample_" + string(rune('a'+pi)) + ".png")
				png.Encode(f, img)
				f.Close()
			}
		}
	}
}

func TestPlainQRRoundTrip(t *testing.T) {
	for _, text := range []string{"x", strings.Repeat("a", 200), strings.Repeat("z", qrMaxText)} {
		q, err := qrcode.New(text, qrcode.Medium)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := decodeQRImage(q.Image(1024)); err != nil || got != text {
			t.Fatalf("len %d: %v", len(text), err)
		}
	}
}

func TestQRParseHex(t *testing.T) {
	for in, ok := range map[string]bool{"ff0000": true, "#FFF": true, "abc": true, "12345": false, "zzzzzz": false, "": false} {
		if _, err := qrParseHex(in); (err == nil) != ok {
			t.Errorf("%q ok=%v", in, err == nil)
		}
	}
}
