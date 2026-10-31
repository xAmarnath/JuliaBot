package extras

import (
	"bytes"
	"fmt"
	"html"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"

	modules "main/modules"

	tg "github.com/xAmarnath/gogram/telegram"
	"github.com/fogleman/gg"
	"github.com/golang/freetype/truetype"
	"github.com/makiuchi-d/gozxing"
	gzqr "github.com/makiuchi-d/gozxing/qrcode"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
)

const qrMaxText = 1200

func qrTextArg(m *tg.NewMessage) string {
	text := strings.TrimSpace(m.Args())
	if text == "" && m.IsReply() {
		if r, err := m.GetReplyMessage(); err == nil && r != nil {
			text = strings.TrimSpace(r.Text())
		}
	}
	return text
}

func qrSendPNG(m *tg.NewMessage, status *modules.Status, img image.Image, caption, name string) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		status.Edit("Couldn't encode the image: " + html.EscapeString(err.Error()))
		return
	}
	status.Done()
	if _, err := modules.TransferReplyMedia(m, buf.Bytes(), &tg.MediaOptions{Caption: caption, FileName: name, MimeType: "image/png"}); err != nil {
		status.Edit("Couldn't send the image: " + html.EscapeString(err.Error()))
	}
}

func qrCaption(text string) string {
	shown := text
	if r := []rune(shown); len(r) > 200 {
		shown = string(r[:200]) + "…"
	}
	return "<b>QR code</b>\n<code>" + html.EscapeString(shown) + "</code>"
}

func QRHandler(m *tg.NewMessage) error {
	text := qrTextArg(m)
	if text == "" {
		m.Reply("Usage: <code>/qr &lt;text&gt;</code> or reply to a message")
		return nil
	}
	if len(text) > qrMaxText {
		m.Reply(fmt.Sprintf("Text is too long for a QR code (max %d characters).", qrMaxText))
		return nil
	}
	status := modules.NewStatus(m, "Generating QR code…")
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		status.Edit("Couldn't make a QR code: " + html.EscapeString(err.Error()))
		return nil
	}
	qrSendPNG(m, status, q.Image(1024), qrCaption(text), "qr.png")
	return nil
}

func qrParseHex(s string) (color.RGBA, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "#")
	if len(s) == 3 {
		s = string([]byte{s[0], s[0], s[1], s[1], s[2], s[2]})
	}
	if len(s) != 6 {
		return color.RGBA{}, fmt.Errorf("invalid hex color")
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return color.RGBA{}, fmt.Errorf("invalid hex color")
	}
	return color.RGBA{uint8(v >> 16), uint8(v >> 8), uint8(v), 255}, nil
}

func qrLuminance(c color.RGBA) float64 {
	return 0.2126*float64(c.R) + 0.7152*float64(c.G) + 0.0722*float64(c.B)
}

func QRColorHandler(m *tg.NewMessage) error {
	fields := strings.Fields(m.Args())
	if len(fields) < 3 {
		m.Reply("Usage: <code>/qrcolor &lt;text&gt; &lt;fg_hex&gt; &lt;bg_hex&gt;</code>\nExample: <code>/qrcolor hello ff0000 ffffff</code>")
		return nil
	}
	fg, err1 := qrParseHex(fields[len(fields)-2])
	bg, err2 := qrParseHex(fields[len(fields)-1])
	if err1 != nil || err2 != nil {
		m.Reply("Colors must be hex like <code>ff0000</code> or <code>#f00</code>.")
		return nil
	}
	text := strings.Join(fields[:len(fields)-2], " ")
	if len(text) > qrMaxText {
		m.Reply(fmt.Sprintf("Text is too long for a QR code (max %d characters).", qrMaxText))
		return nil
	}
	status := modules.NewStatus(m, "Generating QR code…")
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		status.Edit("Couldn't make a QR code: " + html.EscapeString(err.Error()))
		return nil
	}
	q.ForegroundColor, q.BackgroundColor = fg, bg
	caption := qrCaption(text)
	if math.Abs(qrLuminance(fg)-qrLuminance(bg)) < 90 {
		caption += "\n<i>Low contrast between these colors — some scanners may not read it.</i>"
	}
	qrSendPNG(m, status, q.Image(1024), caption, "qr.png")
	return nil
}

var qrArtPalettes = [][3]color.RGBA{
	{{0x7f, 0x5a, 0xf0, 255}, {0x2c, 0xb5, 0xe8, 255}, {0x10, 0x12, 0x2a, 255}},
	{{0xff, 0x5f, 0x6d, 255}, {0xff, 0xc3, 0x71, 255}, {0x1d, 0x10, 0x1f, 255}},
	{{0x11, 0x99, 0x8e, 255}, {0x38, 0xef, 0x7d, 255}, {0x08, 0x1c, 0x1a, 255}},
	{{0xf7, 0x79, 0x7d, 255}, {0xc6, 0x4b, 0xd8, 255}, {0x1a, 0x0b, 0x24, 255}},
}

func qrLerp(a, b color.RGBA, t float64) color.RGBA {
	l := func(x, y uint8) uint8 { return uint8(float64(x) + (float64(y)-float64(x))*t) }
	return color.RGBA{l(a.R, b.R), l(a.G, b.G), l(a.B, b.B), 255}
}

func qrArtFace(bold bool) *truetype.Font {
	for _, p := range []string{"assets/Inter_28pt-Bold.ttf", "assets/NotoSans-Bold.ttf", "assets/GoNotoCurrent-Bold.ttf"} {
		if !bold {
			p = strings.Replace(strings.Replace(p, "-Bold", "-Regular", 1), "Inter_28pt-Regular", "NotoSans-Regular", 1)
		}
		if f := imgFont(p); f != nil {
			return f
		}
	}
	return nil
}

func qrDarkEnough(c color.RGBA) color.RGBA {
	for qrLuminance(c) > 105 {
		c = color.RGBA{uint8(float64(c.R) * 0.88), uint8(float64(c.G) * 0.88), uint8(float64(c.B) * 0.88), 255}
	}
	return c
}

func qrIsFinder(x, y, n int) bool {
	in := func(cx, cy int) bool { return x >= cx && x < cx+7 && y >= cy && y < cy+7 }
	return in(0, 0) || in(n-7, 0) || in(0, n-7)
}

func renderQRArt(text string, palette [3]color.RGBA) (image.Image, error) {
	q, err := qrcode.New(text, qrcode.High)
	if err != nil {
		return nil, err
	}
	q.DisableBorder = true
	bits := q.Bitmap()
	n := len(bits)
	const W, H, pad = 1080, 1350, 110
	cell := float64(W-2*pad-80) / float64(n)
	qrSize := cell * float64(n)
	ox, oy := (float64(W)-qrSize)/2, 230.0

	dc := gg.NewContext(W, H)
	bg := gg.NewLinearGradient(0, 0, W, H)
	bg.AddColorStop(0, palette[2])
	bg.AddColorStop(1, qrLerp(palette[2], palette[0], 0.35))
	dc.SetFillStyle(bg)
	dc.DrawRectangle(0, 0, W, H)
	dc.Fill()

	for i, c := range []struct{ x, y, r float64 }{{120, 140, 260}, {W - 90, H - 220, 320}} {
		g := gg.NewRadialGradient(c.x, c.y, 0, c.x, c.y, c.r)
		col := palette[i]
		g.AddColorStop(0, color.NRGBA{col.R, col.G, col.B, 110})
		g.AddColorStop(1, color.NRGBA{col.R, col.G, col.B, 0})
		dc.SetFillStyle(g)
		dc.DrawCircle(c.x, c.y, c.r)
		dc.Fill()
	}

	dc.SetRGBA255(255, 255, 255, 250)
	dc.DrawRoundedRectangle(ox-40, oy-40, qrSize+80, qrSize+80, 48)
	dc.Fill()

	grad := gg.NewLinearGradient(ox, oy, ox+qrSize, oy+qrSize)
	grad.AddColorStop(0, qrDarkEnough(palette[0]))
	grad.AddColorStop(1, qrDarkEnough(palette[1]))

	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if !bits[y][x] || qrIsFinder(x, y, n) {
				continue
			}
			cx, cy := ox+(float64(x)+0.5)*cell, oy+(float64(y)+0.5)*cell
			dc.DrawCircle(cx, cy, cell*0.46)
		}
	}
	dc.SetFillStyle(grad)
	dc.Fill()

	for _, f := range [][2]int{{0, 0}, {n - 7, 0}, {0, n - 7}} {
		fx, fy := ox+float64(f[0])*cell, oy+float64(f[1])*cell
		dc.DrawRoundedRectangle(fx, fy, 7*cell, 7*cell, 2.2*cell)
		dc.SetFillStyle(grad)
		dc.Fill()
		dc.SetRGBA255(255, 255, 255, 255)
		dc.DrawRoundedRectangle(fx+cell, fy+cell, 5*cell, 5*cell, 1.6*cell)
		dc.Fill()
		dc.DrawRoundedRectangle(fx+2*cell, fy+2*cell, 3*cell, 3*cell, 1.1*cell)
		dc.SetFillStyle(grad)
		dc.Fill()
	}

	if f := qrArtFace(true); f != nil {
		dc.SetFontFace(truetype.NewFace(f, &truetype.Options{Size: 54}))
		dc.SetRGBA255(255, 255, 255, 255)
		dc.DrawStringAnchored("Scan me", W/2, 130, 0.5, 0.5)
	}
	label := text
	if u, err := url.Parse(text); err == nil && u.Host != "" {
		label = u.Host + strings.TrimSuffix(u.Path, "/")
	}
	if f := qrArtFace(false); f != nil {
		dc.SetFontFace(truetype.NewFace(f, &truetype.Options{Size: 36}))
		dc.SetRGBA255(255, 255, 255, 215)
		lines := dc.WordWrap(label, W-2*pad)
		if len(lines) > 2 {
			lines = lines[:2]
			lines[1] = strings.TrimRight(lines[1], " ") + "…"
		}
		for i, line := range lines {
			dc.DrawStringAnchored(line, W/2, oy+qrSize+110+float64(i)*50, 0.5, 0.5)
		}
	}
	return dc.Image(), nil
}

func QRArtHandler(m *tg.NewMessage) error {
	text := qrTextArg(m)
	if text == "" {
		m.Reply("Usage: <code>/qrart &lt;text&gt;</code> or reply to a message")
		return nil
	}
	if len(text) > 600 {
		m.Reply("Text is too long for a styled QR code (max 600 characters). Use /qr for longer text.")
		return nil
	}
	status := modules.NewStatus(m, "Designing your QR code…")
	palette := qrArtPalettes[int(uint32(len(text)*31+int(text[0])))%len(qrArtPalettes)]
	img, err := renderQRArt(text, palette)
	if err != nil {
		status.Edit("Couldn't make a QR code: " + html.EscapeString(err.Error()))
		return nil
	}
	qrSendPNG(m, status, img, qrCaption(text), "qr-art.png")
	return nil
}

func decodeQRImage(img image.Image) (string, error) {
	reader := gzqr.NewQRCodeReader()
	hints := map[gozxing.DecodeHintType]any{gozxing.DecodeHintType_TRY_HARDER: true}
	try := func(src image.Image) (string, error) {
		bmp, err := gozxing.NewBinaryBitmapFromImage(src)
		if err != nil {
			return "", err
		}
		res, err := reader.Decode(bmp, hints)
		if err != nil {
			return "", err
		}
		return res.GetText(), nil
	}
	if text, err := try(img); err == nil {
		return text, nil
	}
	b := img.Bounds()
	for _, target := range []int{1200, 600, 2000} {
		longest := max(b.Dx(), b.Dy())
		if longest == 0 || longest == target {
			continue
		}
		scale := float64(target) / float64(longest)
		dst := image.NewRGBA(image.Rect(0, 0, int(float64(b.Dx())*scale), int(float64(b.Dy())*scale)))
		draw.CatmullRom.Scale(dst, dst.Bounds(), img, b, draw.Src, nil)
		if text, err := try(dst); err == nil {
			return text, nil
		}
	}
	return "", fmt.Errorf("no QR code found")
}

func QRReadHandler(m *tg.NewMessage) error {
	if !m.IsReply() {
		m.Reply("Usage: reply to an image containing a QR code with <code>/qrread</code>")
		return nil
	}
	r, err := m.GetReplyMessage()
	if err != nil || r == nil || !r.IsMedia() {
		m.Reply("The replied message has no image.")
		return nil
	}
	status := modules.NewStatus(m, "Reading QR code…")
	path, err := modules.TransferDownload(r)
	if err != nil {
		status.Edit("Couldn't download the image: " + html.EscapeString(err.Error()))
		return nil
	}
	defer os.Remove(path)
	f, err := os.Open(path)
	if err != nil {
		status.Edit("Couldn't open the image.")
		return nil
	}
	img, _, err := image.Decode(f)
	f.Close()
	if err != nil {
		status.Edit("That file isn't an image I can read (use a photo, PNG, JPG, GIF or WEBP).")
		return nil
	}
	text, err := decodeQRImage(img)
	if err != nil {
		status.Edit("I couldn't find a readable QR code in that image. Try a sharper, closer photo.")
		return nil
	}
	out := "<b>QR decoded</b>\n<code>" + html.EscapeString(text) + "</code>"
	opts := &tg.SendOptions{LinkPreview: false}
	if u, err := url.Parse(text); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		opts.ReplyMarkup = tg.NewKeyboard().AddRow(tg.Button.URL("Open link", text)).Build()
	}
	status.Edit(out, opts)
	return nil
}

func init() {
	modules.QueueHandlerRegistration(func() {
		c := modules.Client
		modules.OnCommand(c, "cmd:qr", QRHandler)
		modules.OnCommand(c, "cmd:qrcolor", QRColorHandler)
		modules.OnCommand(c, "cmd:qrart", QRArtHandler)
		modules.OnCommand(c, "cmd:qrread", QRReadHandler)
	})
}
