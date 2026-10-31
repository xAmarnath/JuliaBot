package extras

import (
	"context"
	"fmt"
	"html"
	"image"
	"image/color"
	"image/draw"
	_ "image/jpeg"
	_ "image/png"
	"io"
	modules "main/modules"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
	"github.com/fogleman/gg"
	"github.com/golang/freetype/truetype"
)

func circleCropApplyMask(src image.Image) image.Image {
	bounds := src.Bounds()
	w := bounds.Dx()
	h := bounds.Dy()
	size := w
	if h < size {
		size = h
	}
	if size <= 0 {
		return src
	}

	offX := bounds.Min.X + (w-size)/2
	offY := bounds.Min.Y + (h-size)/2
	squareRect := image.Rect(offX, offY, offX+size, offY+size)

	square := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(square, square.Bounds(), src, squareRect.Min, draw.Src)

	dc := gg.NewContext(size, size)
	dc.DrawCircle(float64(size)/2, float64(size)/2, float64(size)/2)
	dc.Clip()
	dc.DrawImage(square, 0, 0)
	return dc.Image()
}

func circleCropDecodeFile(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		return nil, err
	}
	return img, nil
}

func circleCropSavePNG(img image.Image, outPath string) error {
	return gg.NewContextForImage(img).SavePNG(outPath)
}

const imgMaxInput = 20 << 20

// imgReplySource returns the replied photo/image-document message, or a user-facing error.
func imgReplySource(m *tg.NewMessage, usage string) (*tg.NewMessage, string) {
	if !m.IsReply() {
		return nil, usage
	}
	r, err := m.GetReplyMessage()
	if err != nil || r == nil {
		return nil, "could not fetch the replied message"
	}
	if r.Photo() != nil {
		return r, ""
	}
	if d := r.Document(); d != nil && strings.HasPrefix(d.MimeType, "image/") {
		if d.Size > imgMaxInput {
			return nil, "image is too large (max 20 MB)"
		}
		return r, ""
	}
	return nil, "the replied message is not an image"
}

func CircleCropHandler(m *tg.NewMessage) error {
	r, msg := imgReplySource(m, "reply to a photo with <code>/circle</code> to crop it into a circle")
	if r == nil {
		m.Reply(msg)
		return nil
	}

	status, _ := m.Reply("<code>cropping into circle...</code>")
	fail := func(msg string) error {
		if status != nil {
			status.Edit(msg)
		} else {
			m.Reply(msg)
		}
		return nil
	}

	inPath := filepath.Join(os.TempDir(), fmt.Sprintf("circle_in_%d", time.Now().UnixNano()))
	got, err := modules.TransferDownload(r, &tg.DownloadOptions{FileName: inPath})
	if got != "" && got != inPath {
		defer os.Remove(got)
	}
	defer os.Remove(inPath)
	if err != nil {
		return fail("error downloading image: " + html.EscapeString(err.Error()))
	}
	if got != "" {
		inPath = got
	}

	src, err := circleCropDecodeFile(inPath)
	if err != nil {
		return fail("error decoding image: " + html.EscapeString(err.Error()))
	}
	b := src.Bounds()
	if b.Dx() <= 0 || b.Dy() <= 0 {
		return fail("invalid image dimensions")
	}

	outPath := filepath.Join(os.TempDir(), fmt.Sprintf("circle_out_%d.png", time.Now().UnixNano()))
	defer os.Remove(outPath)
	if err := circleCropSavePNG(circleCropApplyMask(src), outPath); err != nil {
		return fail("error saving png: " + html.EscapeString(err.Error()))
	}

	side := min(b.Dx(), b.Dy())
	caption := fmt.Sprintf("<b>Circle Crop</b>\n<b>Size:</b> <code>%dx%d</code>", side, side)
	if status != nil {
		status.Delete()
	}
	// Sent as a file so Telegram keeps the transparent corners.
	_, merr := modules.TransferReplyMedia(m, outPath, &tg.MediaOptions{
		Caption:       caption,
		FileName:      "circle.png",
		MimeType:      "image/png",
		ForceDocument: true,
	})
	if merr != nil {
		m.Reply("upload failed: " + html.EscapeString(merr.Error()))
	}
	return nil
}

func registerImageCropHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:circle", CircleCropHandler)
}

func initFromSrc_image_crop_0_1() { modules.QueueHandlerRegistration(registerImageCropHandlers) }

var namedColors = map[string]string{
	"aliceblue":            "#F0F8FF",
	"antiquewhite":         "#FAEBD7",
	"aqua":                 "#00FFFF",
	"aquamarine":           "#7FFFD4",
	"azure":                "#F0FFFF",
	"beige":                "#F5F5DC",
	"bisque":               "#FFE4C4",
	"black":                "#000000",
	"blanchedalmond":       "#FFEBCD",
	"blue":                 "#0000FF",
	"blueviolet":           "#8A2BE2",
	"brown":                "#A52A2A",
	"burlywood":            "#DEB887",
	"cadetblue":            "#5F9EA0",
	"chartreuse":           "#7FFF00",
	"chocolate":            "#D2691E",
	"coral":                "#FF7F50",
	"cornflowerblue":       "#6495ED",
	"cornsilk":             "#FFF8DC",
	"crimson":              "#DC143C",
	"cyan":                 "#00FFFF",
	"darkblue":             "#00008B",
	"darkcyan":             "#008B8B",
	"darkgoldenrod":        "#B8860B",
	"darkgray":             "#A9A9A9",
	"darkgreen":            "#006400",
	"darkkhaki":            "#BDB76B",
	"darkmagenta":          "#8B008B",
	"darkolivegreen":       "#556B2F",
	"darkorange":           "#FF8C00",
	"darkorchid":           "#9932CC",
	"darkred":              "#8B0000",
	"darksalmon":           "#E9967A",
	"darkseagreen":         "#8FBC8F",
	"darkslateblue":        "#483D8B",
	"darkslategray":        "#2F4F4F",
	"darkturquoise":        "#00CED1",
	"darkviolet":           "#9400D3",
	"deeppink":             "#FF1493",
	"deepskyblue":          "#00BFFF",
	"dimgray":              "#696969",
	"dodgerblue":           "#1E90FF",
	"firebrick":            "#B22222",
	"floralwhite":          "#FFFAF0",
	"forestgreen":          "#228B22",
	"fuchsia":              "#FF00FF",
	"gainsboro":            "#DCDCDC",
	"ghostwhite":           "#F8F8FF",
	"gold":                 "#FFD700",
	"goldenrod":            "#DAA520",
	"gray":                 "#808080",
	"green":                "#008000",
	"greenyellow":          "#ADFF2F",
	"honeydew":             "#F0FFF0",
	"hotpink":              "#FF69B4",
	"indianred":            "#CD5C5C",
	"indigo":               "#4B0082",
	"ivory":                "#FFFFF0",
	"khaki":                "#F0E68C",
	"lavender":             "#E6E6FA",
	"lavenderblush":        "#FFF0F5",
	"lawngreen":            "#7CFC00",
	"lemonchiffon":         "#FFFACD",
	"lightblue":            "#ADD8E6",
	"lightcoral":           "#F08080",
	"lightcyan":            "#E0FFFF",
	"lightgoldenrodyellow": "#FAFAD2",
	"lightgray":            "#D3D3D3",
	"lightgreen":           "#90EE90",
	"lightpink":            "#FFB6C1",
	"lightsalmon":          "#FFA07A",
	"lightseagreen":        "#20B2AA",
	"lightskyblue":         "#87CEFA",
	"lightslategray":       "#778899",
	"lightsteelblue":       "#B0C4DE",
	"lightyellow":          "#FFFFE0",
	"lime":                 "#00FF00",
	"limegreen":            "#32CD32",
	"linen":                "#FAF0E6",
	"magenta":              "#FF00FF",
	"maroon":               "#800000",
	"mediumaquamarine":     "#66CDAA",
	"mediumblue":           "#0000CD",
	"mediumorchid":         "#BA55D3",
	"mediumpurple":         "#9370DB",
	"mediumseagreen":       "#3CB371",
	"mediumslateblue":      "#7B68EE",
	"mediumspringgreen":    "#00FA9A",
	"mediumturquoise":      "#48D1CC",
	"mediumvioletred":      "#C71585",
	"midnightblue":         "#191970",
	"mintcream":            "#F5FFFA",
	"mistyrose":            "#FFE4E1",
	"moccasin":             "#FFE4B5",
	"navajowhite":          "#FFDEAD",
	"navy":                 "#000080",
	"oldlace":              "#FDF5E6",
	"olive":                "#808000",
	"olivedrab":            "#6B8E23",
	"orange":               "#FFA500",
	"orangered":            "#FF4500",
	"orchid":               "#DA70D6",
	"palegoldenrod":        "#EEE8AA",
	"palegreen":            "#98FB98",
	"paleturquoise":        "#AFEEEE",
	"palevioletred":        "#DB7093",
	"papayawhip":           "#FFEFD5",
	"peachpuff":            "#FFDAB9",
	"peru":                 "#CD853F",
	"pink":                 "#FFC0CB",
	"plum":                 "#DDA0DD",
	"powderblue":           "#B0E0E6",
	"purple":               "#800080",
	"rebeccapurple":        "#663399",
	"red":                  "#FF0000",
	"rosybrown":            "#BC8F8F",
	"royalblue":            "#4169E1",
	"saddlebrown":          "#8B4513",
	"salmon":               "#FA8072",
	"sandybrown":           "#F4A460",
	"seagreen":             "#2E8B57",
	"seashell":             "#FFF5EE",
	"sienna":               "#A0522D",
	"silver":               "#C0C0C0",
	"skyblue":              "#87CEEB",
	"slateblue":            "#6A5ACD",
	"slategray":            "#708090",
	"snow":                 "#FFFAFA",
	"springgreen":          "#00FF7F",
	"steelblue":            "#4682B4",
	"tan":                  "#D2B48C",
	"teal":                 "#008080",
	"thistle":              "#D8BFD8",
	"tomato":               "#FF6347",
	"turquoise":            "#40E0D0",
	"violet":               "#EE82EE",
	"wheat":                "#F5DEB3",
	"white":                "#FFFFFF",
	"whitesmoke":           "#F5F5F5",
	"yellow":               "#FFFF00",
	"yellowgreen":          "#9ACD32",
}

func colorsParseHex(s string) (color.RGBA, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "#")
	s = strings.ToLower(s)
	if len(s) == 3 {
		s = string([]byte{s[0], s[0], s[1], s[1], s[2], s[2]})
	}
	if len(s) != 6 {
		return color.RGBA{}, fmt.Errorf("invalid hex length")
	}
	r, err := strconv.ParseUint(s[0:2], 16, 8)
	if err != nil {
		return color.RGBA{}, err
	}
	g, err := strconv.ParseUint(s[2:4], 16, 8)
	if err != nil {
		return color.RGBA{}, err
	}
	b, err := strconv.ParseUint(s[4:6], 16, 8)
	if err != nil {
		return color.RGBA{}, err
	}
	return color.RGBA{uint8(r), uint8(g), uint8(b), 0xff}, nil
}

func colorsResolve(token string) (color.RGBA, string, error) {
	t := strings.TrimSpace(token)
	if t == "" {
		return color.RGBA{}, "", fmt.Errorf("empty input")
	}
	lower := strings.ToLower(t)
	lower = strings.ReplaceAll(lower, " ", "")
	if hex, ok := namedColors[lower]; ok {
		c, err := colorsParseHex(hex)
		if err != nil {
			return color.RGBA{}, "", err
		}
		return c, lower, nil
	}
	c, err := colorsParseHex(t)
	if err != nil {
		return color.RGBA{}, "", fmt.Errorf("unknown color: %s", t)
	}
	return c, "", nil
}

func colorsRGBToHSL(c color.RGBA) (float64, float64, float64) {
	r := float64(c.R) / 255.0
	g := float64(c.G) / 255.0
	b := float64(c.B) / 255.0
	max := math.Max(r, math.Max(g, b))
	min := math.Min(r, math.Min(g, b))
	l := (max + min) / 2.0
	if max == min {
		return 0, 0, l
	}
	d := max - min
	var s float64
	if l > 0.5 {
		s = d / (2.0 - max - min)
	} else {
		s = d / (max + min)
	}
	var h float64
	switch max {
	case r:
		h = (g - b) / d
		if g < b {
			h += 6
		}
	case g:
		h = (b-r)/d + 2
	case b:
		h = (r-g)/d + 4
	}
	h /= 6
	return h * 360, s * 100, l * 100
}

func colorsHexFromRGB(c color.RGBA) string {
	return fmt.Sprintf("#%02X%02X%02X", c.R, c.G, c.B)
}

func colorsRelativeLuminance(c color.RGBA) float64 {
	chx := func(v uint8) float64 {
		x := float64(v) / 255.0
		if x <= 0.03928 {
			return x / 12.92
		}
		return math.Pow((x+0.055)/1.055, 2.4)
	}
	return 0.2126*chx(c.R) + 0.7152*chx(c.G) + 0.0722*chx(c.B)
}

func colorsTextColorFor(bg color.RGBA) color.RGBA {
	if colorsRelativeLuminance(bg) > 0.5 {
		return color.RGBA{0x14, 0x14, 0x18, 0xff}
	}
	return color.RGBA{0xff, 0xff, 0xff, 0xff}
}

func colorsLoadFont(dc *gg.Context, size float64) {
	name := modules.GetRandomFont()
	candidates := []string{
		"./assets/" + name,
		"assets/" + name,
		"../assets/" + name,
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "assets", name))
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "assets", name),
			filepath.Join(dir, "..", "assets", name),
		)
	}
	for _, p := range candidates {
		if f := imgFont(p); f != nil {
			dc.SetFontFace(truetype.NewFace(f, &truetype.Options{Size: size}))
			return
		}
	}
}

var imgFontCache sync.Map

// imgFont parses a font file once; gg.LoadFontFace re-reads and re-parses it on every call.
func imgFont(path string) *truetype.Font {
	if v, ok := imgFontCache.Load(path); ok {
		return v.(*truetype.Font)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	f, err := truetype.Parse(data)
	if err != nil {
		return nil
	}
	v, _ := imgFontCache.LoadOrStore(path, f)
	return v.(*truetype.Font)
}

func colorsRenderSwatch(c color.RGBA) (string, error) {
	const W, H = 200, 200
	dc := gg.NewContext(W, H)
	dc.SetRGBA255(int(c.R), int(c.G), int(c.B), 255)
	dc.Clear()

	hex := colorsHexFromRGB(c)
	tc := colorsTextColorFor(c)

	dc.SetRGBA255(int(tc.R), int(tc.G), int(tc.B), 230)
	dc.SetLineWidth(2)
	dc.DrawRectangle(8, 8, W-16, H-16)
	dc.Stroke()

	dc.SetRGBA255(int(tc.R), int(tc.G), int(tc.B), 255)
	colorsLoadFont(dc, 28)
	dc.DrawStringAnchored(hex, W/2, H/2-8, 0.5, 0.5)

	colorsLoadFont(dc, 14)
	dc.DrawStringAnchored(fmt.Sprintf("rgb %d %d %d", c.R, c.G, c.B), W/2, H/2+22, 0.5, 0.5)

	out := filepath.Join(os.TempDir(), fmt.Sprintf("color_%d.png", time.Now().UnixNano()))
	if err := dc.SavePNG(out); err != nil {
		return "", err
	}
	return out, nil
}

func colorsDistance(a, b color.RGBA) float64 {
	dr := float64(a.R) - float64(b.R)
	dg := float64(a.G) - float64(b.G)
	db := float64(a.B) - float64(b.B)
	return math.Sqrt(dr*dr + dg*dg + db*db)
}

type colorMatch struct {
	Name string
	Hex  string
	Dist float64
}

func colorsNearest(target color.RGBA, n int) []colorMatch {
	matches := make([]colorMatch, 0, len(namedColors))
	for name, hex := range namedColors {
		c, err := colorsParseHex(hex)
		if err != nil {
			continue
		}
		matches = append(matches, colorMatch{
			Name: name,
			Hex:  hex,
			Dist: colorsDistance(target, c),
		})
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Dist < matches[j].Dist
	})
	if len(matches) > n {
		matches = matches[:n]
	}
	return matches
}

func ColorHandler(m *tg.NewMessage) error {
	arg := strings.TrimSpace(m.Args())
	if arg == "" {
		m.Reply("usage: <code>/color &lt;name_or_hex&gt;</code>\nexamples: <code>/color red</code> or <code>/color #FF0000</code>")
		return nil
	}
	token := strings.Fields(arg)[0]
	c, name, err := colorsResolve(token)
	if err != nil {
		m.Reply("invalid color: " + html.EscapeString(token))
		return nil
	}

	status, _ := m.Reply("<code>rendering swatch...</code>")

	out, err := colorsRenderSwatch(c)
	if err != nil {
		msg := "failed to render: " + html.EscapeString(err.Error())
		if status != nil {
			status.Edit(msg)
		} else {
			m.Reply(msg)
		}
		return nil
	}

	h, s, l := colorsRGBToHSL(c)
	hex := colorsHexFromRGB(c)

	var b strings.Builder
	b.WriteString("<b>Color</b>\n")
	if name != "" {
		b.WriteString(fmt.Sprintf("name  <code>%s</code>\n", html.EscapeString(name)))
	}
	b.WriteString(fmt.Sprintf("hex   <code>%s</code>\n", hex))
	b.WriteString(fmt.Sprintf("rgb   <code>%d, %d, %d</code>\n", c.R, c.G, c.B))
	b.WriteString(fmt.Sprintf("hsl   <code>%.0f, %.0f%%, %.0f%%</code>", h, s, l))

	if status != nil {
		status.Delete()
	}

	_, merr := modules.TransferReplyMedia(m, out, &tg.MediaOptions{
		Caption:  b.String(),
		FileName: "color.png",
		MimeType: "image/png",
	})
	os.Remove(out)
	if merr != nil {
		m.Reply("upload failed: " + html.EscapeString(merr.Error()))
	}
	return nil
}

func ColorsHandler(m *tg.NewMessage) error {
	arg := strings.TrimSpace(m.Args())
	if arg == "" {
		m.Reply("usage: <code>/colors &lt;hex_or_name&gt;</code>\nexample: <code>/colors #ff6a3d</code>")
		return nil
	}
	token := strings.Fields(arg)[0]
	c, _, err := colorsResolve(token)
	if err != nil {
		m.Reply("invalid color: " + html.EscapeString(token))
		return nil
	}

	matches := colorsNearest(c, 8)
	if len(matches) == 0 {
		m.Reply("no matches found")
		return nil
	}

	var b strings.Builder
	b.WriteString("<b>Nearest Named Colors</b>\n")
	b.WriteString(fmt.Sprintf("input  <code>%s</code>\n\n", colorsHexFromRGB(c)))
	for i, mt := range matches {
		b.WriteString(fmt.Sprintf("%d. <b>%s</b>  <code>%s</code>  Δ %.0f\n",
			i+1, html.EscapeString(mt.Name), mt.Hex, mt.Dist))
	}
	m.Reply(b.String())
	return nil
}

func registerColorsHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:color", ColorHandler)
	modules.OnCommand(c, "cmd:colors", ColorsHandler)
}

func initFromSrc_colors_1_1() {
	modules.QueueHandlerRegistration(registerColorsHandlers)
}

// imgDownloadTemp streams an image URL into a temp file (capped at imgMaxInput).
func imgDownloadTemp(ctx context.Context, target, pattern string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", browserUA)
	resp, err := extHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &httpStatusError{Code: resp.StatusCode}
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "image/") {
		return "", fmt.Errorf("unexpected content-type %q", ct)
	}
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, imgMaxInput+1))
	f.Close()
	switch {
	case err != nil:
	case n == 0:
		err = fmt.Errorf("empty image response")
	case n > imgMaxInput:
		err = fmt.Errorf("image exceeds %d MB", imgMaxInput>>20)
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func WallpaperHandler(m *tg.NewMessage) error {
	seed := strings.TrimSpace(m.Args())
	status := modules.NewStatus(m, "Fetching a wallpaper…")
	endpoint := fmt.Sprintf("https://picsum.photos/1280/720?random=%d", time.Now().UnixNano())
	label := "random"
	if seed != "" && !strings.EqualFold(seed, "random") {
		if r := []rune(seed); len(r) > 64 {
			seed = string(r[:64])
		}
		endpoint = "https://picsum.photos/seed/" + url.PathEscape(seed) + "/1280/720"
		label = "seed: " + seed
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	path, err := imgDownloadTemp(ctx, endpoint, "wallpaper-*.jpg")
	if err != nil {
		status.Edit("error fetching wallpaper: " + html.EscapeString(err.Error()))
		return nil
	}
	defer os.Remove(path)

	caption := "<b>Wallpaper</b> · 1280x720\n<code>" + html.EscapeString(label) + "</code>"
	status.Done()
	if _, err = modules.TransferReplyMedia(m, path, &tg.MediaOptions{Caption: caption}); err != nil {
		status.Edit("error sending wallpaper: " + html.EscapeString(err.Error()))
	}
	return nil
}

func initFromSrc_wallpaper_2_1() { modules.QueueHandlerRegistration(registerWallpaperHandlers) }

func registerWallpaperHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:wallpaper", WallpaperHandler)
}

var ssURLRe = regexp.MustCompile(`(?i)(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/\S*)?`)

func ScreenshotHandler(m *tg.NewMessage) error {
	src := strings.TrimSpace(m.Args())
	if src == "" && m.IsReply() {
		if r, err := m.GetReplyMessage(); err == nil && r != nil {
			src = r.Text()
		}
	}
	target := ssURLRe.FindString(src)
	if target == "" {
		m.Reply("usage: <code>/ss &lt;url&gt;</code> or reply to a message containing a link")
		return nil
	}
	if lt := strings.ToLower(target); !strings.HasPrefix(lt, "http://") && !strings.HasPrefix(lt, "https://") {
		target = "https://" + target
	}
	if u, err := url.Parse(target); err != nil || u.Host == "" {
		m.Reply("invalid url, must be http(s)")
		return nil
	}

	status, _ := m.Reply("<code>capturing screenshot...</code>")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	path, err := imgDownloadTemp(ctx, "https://image.thum.io/get/width/1280/"+target, "ss-*.png")
	if err != nil {
		msg := "error fetching screenshot: " + html.EscapeString(err.Error())
		if status != nil {
			status.Edit(msg)
		} else {
			m.Reply(msg)
		}
		return nil
	}
	defer os.Remove(path)

	if status != nil {
		status.Delete()
	}
	caption := "<b>Screenshot</b>\n<a href=\"" + html.EscapeString(target) + "\">" + html.EscapeString(target) + "</a>"
	if _, merr := modules.TransferReplyMedia(m, path, &tg.MediaOptions{
		Caption:  caption,
		FileName: "screenshot.png",
		MimeType: "image/png",
	}); merr != nil {
		m.Reply("error sending: " + html.EscapeString(merr.Error()))
	}
	return nil
}

func initFromSrc_screenshot_4_1() { modules.QueueHandlerRegistration(registerScreenshotHandlers) }

func registerScreenshotHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:ss", ScreenshotHandler)
}

func init() {
	initFromSrc_image_crop_0_1()
	initFromSrc_colors_1_1()
	initFromSrc_wallpaper_2_1()
	initFromSrc_screenshot_4_1()

	modules.Mods.AddModule("Images", `<b>Images Module</b>

<b>Commands:</b>
 - /circle — reply to a photo or image file to crop it into a transparent circle PNG
 - /color &lt;name|hex&gt; — color swatch with hex, RGB and HSL
 - /colors &lt;hex|name&gt; — nearest named CSS colors
 - /wallpaper [seed] — random 1280x720 wallpaper; a seed always returns the same image
 - /ss &lt;url&gt; — website screenshot (or reply to a message containing a link)

<b>Examples:</b>
 - <code>/color #FF6A3D</code>
 - <code>/colors teal</code>
 - <code>/wallpaper ocean</code>
 - <code>/ss github.com</code>`)

	modules.Mods.AddModule("Profile", `<b>Profile</b>
/avatar [@user|id] — full-size profile photo of you, a replied user, or the given user
Your player card is <code>/card</code> in the Game section.`)
}
