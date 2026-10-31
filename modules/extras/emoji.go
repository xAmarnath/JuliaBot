package extras

import (
	"bytes"
	"github.com/fogleman/gg"
	"golang.org/x/image/draw"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type textSeg struct {
	text  string
	emoji bool
}

func isEmojiBase(r rune) bool {
	return (r >= 0x1F000 && r <= 0x1FAFF) || (r >= 0x2600 && r <= 0x27BF) || (r >= 0x2B00 && r <= 0x2BFF) ||
		(r >= 0x231A && r <= 0x23FF) || r == 0x2122 || r == 0x2139 || r == 0x203C || r == 0x2049 || r == 0x3030 || r == 0x303D
}

func isEmojiJoiner(r rune) bool {
	return r == 0xFE0F || r == 0x20E3 || (r >= 0x1F3FB && r <= 0x1F3FF) || (r >= 0xE0020 && r <= 0xE007F)
}

func splitEmoji(s string) []textSeg {
	rs := []rune(s)
	var out []textSeg
	var plain []rune
	flush := func() {
		if len(plain) > 0 {
			out = append(out, textSeg{string(plain), false})
			plain = nil
		}
	}
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		keycap := (r >= '0' && r <= '9' || r == '#' || r == '*') && i+1 < len(rs) && (rs[i+1] == 0xFE0F || rs[i+1] == 0x20E3)
		flag := r >= 0x1F1E6 && r <= 0x1F1FF && i+1 < len(rs) && rs[i+1] >= 0x1F1E6 && rs[i+1] <= 0x1F1FF
		if !isEmojiBase(r) && !keycap && !(i+1 < len(rs) && rs[i+1] == 0xFE0F && r > 0x7F) {
			if r != 0xFE0F && r != 0x200D {
				plain = append(plain, r)
			}
			continue
		}
		flush()
		cluster := []rune{r}
		j := i + 1
		if flag {
			cluster = append(cluster, rs[j])
			j++
		}
		for j < len(rs) {
			if isEmojiJoiner(rs[j]) {
				cluster = append(cluster, rs[j])
				j++
				continue
			}
			if rs[j] == 0x200D && j+1 < len(rs) {
				cluster = append(cluster, rs[j], rs[j+1])
				j += 2
				continue
			}
			break
		}
		out = append(out, textSeg{string(cluster), true})
		i = j - 1
	}
	flush()
	return out
}

func twemojiName(cluster string, keepFE0F bool) string {
	hasZWJ := strings.ContainsRune(cluster, 0x200D)
	var parts []string
	for _, r := range cluster {
		if r == 0xFE0F && !keepFE0F && !hasZWJ {
			continue
		}
		parts = append(parts, strconv.FormatInt(int64(r), 16))
	}
	return strings.Join(parts, "-")
}

var (
	emojiCache   sync.Map
	emojiHTTP    = &http.Client{Timeout: 8 * time.Second}
	emojiDiskDir = "tmp/twemoji"
)

func emojiImage(cluster string) image.Image {
	if v, ok := emojiCache.Load(cluster); ok {
		img, _ := v.(image.Image)
		return img
	}
	var img image.Image
	for _, keep := range []bool{false, true} {
		name := twemojiName(cluster, keep)
		path := emojiDiskDir + "/" + name + ".png"
		if fh, err := os.Open(path); err == nil {
			img, _ = png.Decode(fh)
			fh.Close()
		}
		if img == nil {
			resp, err := emojiHTTP.Get("https://cdn.jsdelivr.net/gh/jdecked/twemoji@15.1.0/assets/72x72/" + name + ".png")
			if err == nil {
				data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					if decoded, err := png.Decode(bytes.NewReader(data)); err == nil {
						img = decoded
						_ = os.MkdirAll(emojiDiskDir, 0o755)
						_ = os.WriteFile(path, data, 0o644)
					}
				}
			}
		}
		if img != nil {
			break
		}
	}
	emojiCache.Store(cluster, img)
	return img
}

func richClean(f ghFonts, bold bool, s string) string {
	ft := f.reg
	if bold {
		ft = f.bold
	}
	var b strings.Builder
	for _, r := range s {
		if r == ' ' || ft.Index(r) != 0 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func richMeasure(dc *gg.Context, f ghFonts, bold bool, size float64, s string) float64 {
	dc.SetFontFace(f.face(bold, size))
	es := dc.FontHeight() * 1.18
	var w float64
	for _, seg := range splitEmoji(s) {
		if seg.emoji {
			w += es + 2
		} else {
			sw, _ := dc.MeasureString(richClean(f, bold, seg.text))
			w += sw
		}
	}
	return w
}

func richFit(dc *gg.Context, f ghFonts, bold bool, size float64, s string, maxW float64) string {
	if richMeasure(dc, f, bold, size, s) <= maxW {
		return s
	}
	r := []rune(s)
	for len(r) > 1 {
		r = r[:len(r)-1]
		if richMeasure(dc, f, bold, size, string(r)+"…") <= maxW {
			return strings.TrimSpace(string(r)) + "…"
		}
	}
	return s
}

func richDraw(dc *gg.Context, f ghFonts, bold bool, size float64, c color.Color, s string, x, y, ax, ay float64) {
	dc.SetFontFace(f.face(bold, size))
	dc.SetColor(c)
	h := dc.FontHeight()
	es := h * 1.18
	total := richMeasure(dc, f, bold, size, s)
	cx := x - ax*total
	baseline := y + ay*h
	for _, seg := range splitEmoji(s) {
		if !seg.emoji {
			txt := richClean(f, bold, seg.text)
			dc.SetColor(c)
			dc.DrawString(txt, cx, baseline)
			sw, _ := dc.MeasureString(txt)
			cx += sw
			continue
		}
		if img := emojiImage(seg.text); img != nil {
			sz := int(es)
			scaled := image.NewRGBA(image.Rect(0, 0, sz, sz))
			draw.CatmullRom.Scale(scaled, scaled.Bounds(), img, img.Bounds(), draw.Over, nil)
			dc.DrawImage(scaled, int(cx+1), int(baseline-h*0.98))
		}
		cx += es + 2
	}
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}
