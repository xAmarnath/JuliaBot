package extras

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"image"
	"image/color"
	"image/png"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	modules "main/modules"

	tg "github.com/xAmarnath/gogram/telegram"
	"github.com/fogleman/gg"
	"github.com/golang/freetype/truetype"
	"golang.org/x/image/draw"
	"golang.org/x/image/font"
)

type ghGraphData struct {
	User    ghUser
	Repos   []ghRepo
	Days    []ghContribDay
	Total   int
	Avatar  image.Image
	Created time.Time
}

type ghLangShare struct {
	Name  string
	Share float64
}

var ghLangColors = map[string]string{
	"Go": "#00ADD8", "Python": "#3572A5", "JavaScript": "#F1E05A", "TypeScript": "#3178C6", "Rust": "#DEA584",
	"Java": "#B07219", "Kotlin": "#A97BFF", "C": "#555555", "C++": "#F34B7D", "C#": "#178600", "Ruby": "#701516",
	"PHP": "#4F5D95", "Swift": "#F05138", "Dart": "#00B4AB", "Shell": "#89E051", "HTML": "#E34C26", "CSS": "#663399",
	"Vue": "#41B883", "Lua": "#000080", "Jupyter Notebook": "#DA5B0B", "Haskell": "#5E5086", "Elixir": "#6E4A7E",
	"Scala": "#C22D40", "Zig": "#EC915C", "Nix": "#7E7EFF", "Svelte": "#FF3E00", "Objective-C": "#438EFF",
}

func ghHex(s string) color.RGBA {
	c, err := qrParseHex(s)
	if err != nil {
		return color.RGBA{0x8b, 0x94, 0x9e, 255}
	}
	return c
}

func ghLangColor(lang string) color.RGBA {
	if h, ok := ghLangColors[lang]; ok {
		return ghHex(h)
	}
	var sum int
	for _, r := range lang {
		sum = sum*31 + int(r)
	}
	h := float64(uint32(sum)%360) / 360
	return ghHSL(h, 0.55, 0.6)
}

func ghHSL(h, s, l float64) color.RGBA {
	f := func(n float64) uint8 {
		k := math.Mod(n+h*12, 12)
		a := s * math.Min(l, 1-l)
		return uint8(255 * (l - a*math.Max(-1, math.Min(math.Min(k-3, 9-k), 1))))
	}
	return color.RGBA{f(0), f(8), f(4), 255}
}

func ghFetchAllRepos(name string) ([]ghRepo, error) {
	var all []ghRepo
	for page := 1; page <= 3; page++ {
		body, status, err := ghDoRequest(fmt.Sprintf("https://api.github.com/users/%s/repos?per_page=100&type=owner&sort=pushed&page=%d", name, page), "")
		if err != nil {
			return nil, err
		}
		if status != 200 {
			return nil, fmt.Errorf("api status %d", status)
		}
		var batch []ghRepo
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			break
		}
	}
	return all, nil
}

func ghFetchAvatar(u string) image.Image {
	if u == "" {
		return nil
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(u + "&s=400")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	img, _, err := image.Decode(resp.Body)
	if err != nil {
		return nil
	}
	return img
}

func ghLanguageShares(repos []ghRepo) []ghLangShare {
	weights := map[string]float64{}
	var total float64
	for _, r := range repos {
		if r.Fork || r.Language == "" {
			continue
		}
		w := 1 + math.Log1p(float64(r.Size)) + 2*math.Log1p(float64(r.StargazersCount))
		weights[r.Language] += w
		total += w
	}
	var out []ghLangShare
	for k, v := range weights {
		out = append(out, ghLangShare{k, v / total})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Share > out[j].Share })
	if len(out) > 6 {
		var rest float64
		for _, l := range out[6:] {
			rest += l.Share
		}
		out = append(out[:6], ghLangShare{"Other", rest})
	}
	return out
}

func ghPowerLevel(d *ghGraphData, stars int, longest int) (int, string) {
	score := 18*math.Log10(1+float64(stars)) + 14*math.Log10(1+float64(d.User.Followers)) +
		16*math.Log10(1+float64(d.Total)) + 8*math.Log10(1+float64(longest)) + 6*math.Log10(1+float64(d.User.PublicRepos))
	lvl := int(math.Min(99, math.Max(1, score/2.5)))
	ranks := []struct {
		min  int
		name string
	}{{90, "Legend"}, {75, "Grandmaster"}, {60, "Master"}, {45, "Expert"}, {30, "Builder"}, {15, "Apprentice"}, {0, "Newcomer"}}
	for _, r := range ranks {
		if lvl >= r.min {
			return lvl, r.name
		}
	}
	return lvl, "Newcomer"
}

func ghShort(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 10_000:
		return fmt.Sprintf("%.0fk", float64(n)/1e3)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return fmt.Sprint(n)
}

type ghFonts struct{ bold, reg *truetype.Font }

func (f ghFonts) face(bold bool, size float64) font.Face {
	ft := f.reg
	if bold {
		ft = f.bold
	}
	return truetype.NewFace(ft, &truetype.Options{Size: size})
}

func ghLoadFonts() (ghFonts, error) {
	var f ghFonts
	for _, p := range []string{"assets/NotoSans-Bold.ttf", "assets/GoNotoCurrent-Bold.ttf"} {
		if f.bold = imgFont(p); f.bold != nil {
			break
		}
	}
	for _, p := range []string{"assets/NotoSans-Regular.ttf", "assets/GoNotoCurrent-Regular.ttf"} {
		if f.reg = imgFont(p); f.reg != nil {
			break
		}
	}
	if f.bold == nil || f.reg == nil {
		return f, fmt.Errorf("fonts missing")
	}
	return f, nil
}

func ghRenderable(f *truetype.Font, s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == ' ' || f.Index(r) != 0 {
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func ghStar(dc *gg.Context, cx, cy, r float64) {
	for i := 0; i < 10; i++ {
		rad := r
		if i%2 == 1 {
			rad = r * 0.45
		}
		a := -math.Pi/2 + float64(i)*math.Pi/5
		if i == 0 {
			dc.MoveTo(cx+rad*math.Cos(a), cy+rad*math.Sin(a))
		} else {
			dc.LineTo(cx+rad*math.Cos(a), cy+rad*math.Sin(a))
		}
	}
	dc.ClosePath()
	dc.Fill()
}

func ghFork(dc *gg.Context, cx, cy, r float64) {
	dc.SetLineWidth(2.2)
	dc.DrawCircle(cx-r*0.55, cy-r*0.7, r*0.28)
	dc.DrawCircle(cx+r*0.55, cy-r*0.7, r*0.28)
	dc.DrawCircle(cx, cy+r*0.75, r*0.28)
	dc.Stroke()
	dc.MoveTo(cx-r*0.55, cy-r*0.42)
	dc.LineTo(cx-r*0.55, cy-r*0.05)
	dc.LineTo(cx, cy+r*0.2)
	dc.LineTo(cx+r*0.55, cy-r*0.05)
	dc.LineTo(cx+r*0.55, cy-r*0.42)
	dc.MoveTo(cx, cy+r*0.2)
	dc.LineTo(cx, cy+r*0.47)
	dc.Stroke()
}

func ghPanel(dc *gg.Context, x, y, w, h float64) {
	dc.SetRGBA255(255, 255, 255, 10)
	dc.DrawRoundedRectangle(x, y, w, h, 22)
	dc.Fill()
	dc.SetRGBA255(255, 255, 255, 22)
	dc.SetLineWidth(1.5)
	dc.DrawRoundedRectangle(x, y, w, h, 22)
	dc.Stroke()
}

func ghFit(dc *gg.Context, s string, maxW float64) string {
	if w, _ := dc.MeasureString(s); w <= maxW {
		return s
	}
	r := []rune(s)
	for len(r) > 1 {
		r = r[:len(r)-1]
		if w, _ := dc.MeasureString(string(r) + "…"); w <= maxW {
			return string(r) + "…"
		}
	}
	return s
}

func renderGHGraph(d *ghGraphData) (image.Image, error) {
	fonts, err := ghLoadFonts()
	if err != nil {
		return nil, err
	}
	const W, H = 1600, 1180
	dc := gg.NewContext(W, H)
	bg := gg.NewLinearGradient(0, 0, W, H)
	bg.AddColorStop(0, ghHex("#0b0f19"))
	bg.AddColorStop(1, ghHex("#161b2e"))
	dc.SetFillStyle(bg)
	dc.DrawRectangle(0, 0, W, H)
	dc.Fill()
	for _, g := range []struct {
		x, y, r float64
		c       color.RGBA
	}{{180, 120, 420, ghHex("#7c3aed")}, {W - 120, 260, 380, ghHex("#0ea5e9")}, {W / 2, H + 80, 520, ghHex("#22c55e")}} {
		rg := gg.NewRadialGradient(g.x, g.y, 0, g.x, g.y, g.r)
		rg.AddColorStop(0, color.NRGBA{g.c.R, g.c.G, g.c.B, 55})
		rg.AddColorStop(1, color.NRGBA{g.c.R, g.c.G, g.c.B, 0})
		dc.SetFillStyle(rg)
		dc.DrawCircle(g.x, g.y, g.r)
		dc.Fill()
	}

	stars, forks := 0, 0
	var own []ghRepo
	for _, r := range d.Repos {
		if r.Fork {
			continue
		}
		own = append(own, r)
		stars += r.StargazersCount
		forks += r.ForksCount
	}
	current, longest, _, activeDays := ghContribStreaks(d.Days)
	level, rank := ghPowerLevel(d, stars, longest)

	const ax, ay, ar = 70.0, 60.0, 80.0
	ring := gg.NewLinearGradient(ax, ay, ax+2*ar, ay+2*ar)
	ring.AddColorStop(0, ghHex("#a78bfa"))
	ring.AddColorStop(1, ghHex("#22d3ee"))
	dc.SetFillStyle(ring)
	dc.DrawCircle(ax+ar, ay+ar, ar+6)
	dc.Fill()
	if d.Avatar != nil {
		sz := int(2 * ar)
		av := image.NewRGBA(image.Rect(0, 0, sz, sz))
		draw.CatmullRom.Scale(av, av.Bounds(), d.Avatar, d.Avatar.Bounds(), draw.Src, nil)
		dc.Push()
		dc.DrawCircle(ax+ar, ay+ar, ar)
		dc.Clip()
		dc.DrawImage(av, int(ax), int(ay))
		dc.ResetClip()
		dc.Pop()
	} else {
		dc.SetHexColor("#1f2937")
		dc.DrawCircle(ax+ar, ay+ar, ar)
		dc.Fill()
	}

	name := d.User.Name
	if name == "" {
		name = d.User.Login
	}
	tx := ax + 2*ar + 40
	richDraw(dc, fonts, true, 54, color.White, richFit(dc, fonts, true, 54, name, 820), tx, ay+62, 0, 0)
	dc.SetFontFace(fonts.face(false, 28))
	dc.SetRGBA255(167, 139, 250, 255)
	dc.DrawString("@"+d.User.Login, tx, ay+106)
	if bio := strings.TrimSpace(strings.Join(strings.Fields(d.User.Bio), " ")); bio != "" {
		richDraw(dc, fonts, false, 24, color.RGBA{203, 213, 225, 255}, richFit(dc, fonts, false, 24, bio, 860), tx, ay+146, 0, 0)
	}
	var meta []string
	if d.User.Location != "" {
		meta = append(meta, d.User.Location)
	}
	if d.User.Company != "" {
		meta = append(meta, d.User.Company)
	}
	if !d.Created.IsZero() {
		meta = append(meta, "Joined "+d.Created.Format("Jan 2006"))
	}
	if len(meta) > 0 {
		line := strings.Join(meta, "   •   ")
		richDraw(dc, fonts, false, 22, color.RGBA{148, 163, 184, 255}, richFit(dc, fonts, false, 22, line, 860), tx, ay+184, 0, 0)
	}

	bx, by, bw, bh := float64(W-70-330), 52.0, 330.0, 190.0
	badge := gg.NewLinearGradient(bx, by, bx+bw, by+bh)
	badge.AddColorStop(0, ghHex("#7c3aed"))
	badge.AddColorStop(1, ghHex("#0891b2"))
	dc.SetFillStyle(badge)
	dc.DrawRoundedRectangle(bx, by, bw, bh, 28)
	dc.Fill()
	dc.SetRGBA255(255, 255, 255, 200)
	dc.SetFontFace(fonts.face(false, 22))
	dc.DrawStringAnchored("POWER LEVEL", bx+bw/2, by+38, 0.5, 0.5)
	dc.SetRGB255(255, 255, 255)
	dc.SetFontFace(fonts.face(true, 78))
	dc.DrawStringAnchored(fmt.Sprint(level), bx+bw/2, by+102, 0.5, 0.5)
	dc.SetFontFace(fonts.face(true, 28))
	dc.DrawStringAnchored(strings.ToUpper(rank), bx+bw/2, by+160, 0.5, 0.5)

	tiles := []struct{ label, value string }{
		{"Repositories", ghShort(d.User.PublicRepos)}, {"Stars earned", ghShort(stars)}, {"Forks", ghShort(forks)},
		{"Followers", ghShort(d.User.Followers)}, {"Contributions", ghShort(d.Total)}, {"Longest streak", fmt.Sprintf("%dd", longest)},
	}
	tw, tgap, ty := (float64(W)-140-5*20)/6, 20.0, 290.0
	for i, t := range tiles {
		x := 70 + float64(i)*(tw+tgap)
		ghPanel(dc, x, ty, tw, 120)
		dc.SetRGB255(255, 255, 255)
		dc.SetFontFace(fonts.face(true, 46))
		dc.DrawStringAnchored(t.value, x+tw/2, ty+52, 0.5, 0.5)
		dc.SetRGBA255(148, 163, 184, 255)
		dc.SetFontFace(fonts.face(false, 20))
		dc.DrawStringAnchored(t.label, x+tw/2, ty+94, 0.5, 0.5)
	}

	hx, hy, hw, hh := 70.0, 440.0, float64(W-140), 270.0
	ghPanel(dc, hx, hy, hw, hh)
	dc.SetRGB255(255, 255, 255)
	dc.SetFontFace(fonts.face(true, 26))
	dc.DrawString(fmt.Sprintf("%s contributions in the last year", ghShort(d.Total)), hx+30, hy+46)
	days := d.Days
	if len(days) > 371 {
		days = days[len(days)-371:]
	}
	maxCount := 1
	for _, day := range days {
		maxCount = max(maxCount, day.ContributionCount)
	}
	levels := []color.RGBA{ghHex("#1f2937"), ghHex("#0e4429"), ghHex("#006d32"), ghHex("#26a641"), ghHex("#39d353")}
	cell, gap := 21.0, 4.0
	gx, gy := hx+70, hy+86
	offset := 0
	if len(days) > 0 {
		if t, err := time.Parse("2006-01-02", days[0].Date); err == nil {
			offset = int(t.Weekday())
		}
	}
	lastMonth, lastLabelCol := -1, -10
	dc.SetFontFace(fonts.face(false, 18))
	for i, day := range days {
		idx := i + offset
		col, row := idx/7, idx%7
		x, y := gx+float64(col)*(cell+gap), gy+float64(row)*(cell+gap)
		lvl := 0
		if day.ContributionCount > 0 {
			lvl = 1 + int(math.Min(3, math.Floor(4*math.Sqrt(float64(day.ContributionCount)/float64(maxCount)))))
		}
		c := levels[lvl]
		dc.SetRGB255(int(c.R), int(c.G), int(c.B))
		dc.DrawRoundedRectangle(x, y, cell, cell, 5)
		dc.Fill()
		if t, err := time.Parse("2006-01-02", day.Date); err == nil && row == 0 && int(t.Month()) != lastMonth {
			lastMonth = int(t.Month())
			if col-lastLabelCol >= 3 {
				lastLabelCol = col
				dc.SetRGBA255(148, 163, 184, 255)
				dc.DrawString(t.Format("Jan"), x, gy-12)
			}
		}
	}
	dc.SetRGBA255(148, 163, 184, 255)
	for i, l := range []string{"Mon", "Wed", "Fri"} {
		dc.DrawStringAnchored(l, gx-14, gy+float64(1+2*i)*(cell+gap)+cell/2, 1, 0.5)
	}
	lx := hx + hw - 30 - 5*(cell+gap) - 90
	dc.DrawStringAnchored("Less", lx-10, hy+44, 1, 0.5)
	for i, c := range levels {
		dc.SetRGB255(int(c.R), int(c.G), int(c.B))
		dc.DrawRoundedRectangle(lx+float64(i)*(cell+gap), hy+34, cell, cell, 5)
		dc.Fill()
	}
	dc.SetRGBA255(148, 163, 184, 255)
	dc.DrawString("More", lx+5*(cell+gap)+6, hy+51)

	py, ph := 740.0, 380.0
	ghPanel(dc, 70, py, 470, ph)
	dc.SetRGB255(255, 255, 255)
	dc.SetFontFace(fonts.face(true, 26))
	dc.DrawString("Languages", 100, py+46)
	langs := ghLanguageShares(own)
	cx, cy, rOut, rIn := 205.0, py+215, 115.0, 70.0
	if len(langs) == 0 {
		dc.SetRGBA255(148, 163, 184, 255)
		dc.SetFontFace(fonts.face(false, 22))
		dc.DrawStringAnchored("No language data", 305, py+200, 0.5, 0.5)
	} else {
		start := -math.Pi / 2
		for _, l := range langs {
			end := start + 2*math.Pi*l.Share
			c := ghLangColor(l.Name)
			if l.Name == "Other" {
				c = ghHex("#475569")
			}
			dc.SetRGB255(int(c.R), int(c.G), int(c.B))
			dc.MoveTo(cx+rIn*math.Cos(start), cy+rIn*math.Sin(start))
			dc.DrawArc(cx, cy, rOut, start, end)
			dc.DrawArc(cx, cy, rIn, end, start)
			dc.ClosePath()
			dc.Fill()
			start = end
		}
		dc.SetRGB255(255, 255, 255)
		dc.SetFontFace(fonts.face(true, 30))
		dc.DrawStringAnchored(fmt.Sprint(len(langs)), cx, cy-8, 0.5, 0.5)
		dc.SetFontFace(fonts.face(false, 16))
		dc.SetRGBA255(148, 163, 184, 255)
		dc.DrawStringAnchored("languages", cx, cy+20, 0.5, 0.5)
		for i, l := range langs {
			y := py + 110 + float64(i)*36
			c := ghLangColor(l.Name)
			if l.Name == "Other" {
				c = ghHex("#475569")
			}
			dc.SetRGB255(int(c.R), int(c.G), int(c.B))
			dc.DrawCircle(355, y, 8)
			dc.Fill()
			dc.SetRGB255(226, 232, 240)
			dc.SetFontFace(fonts.face(false, 19))
			dc.DrawString(ghFit(dc, l.Name, 100), 372, y+7)
			dc.SetRGBA255(148, 163, 184, 255)
			dc.DrawStringAnchored(fmt.Sprintf("%.0f%%", l.Share*100), 518, y, 1, 0.5)
		}
	}

	rx, rw := 560.0, 540.0
	ghPanel(dc, rx, py, rw, ph)
	dc.SetRGB255(255, 255, 255)
	dc.SetFontFace(fonts.face(true, 26))
	dc.DrawString("Top repositories", rx+30, py+46)
	top := append([]ghRepo(nil), own...)
	sort.Slice(top, func(i, j int) bool {
		if top[i].StargazersCount != top[j].StargazersCount {
			return top[i].StargazersCount > top[j].StargazersCount
		}
		return top[i].ForksCount > top[j].ForksCount
	})
	if len(top) > 5 {
		top = top[:5]
	}
	for i, r := range top {
		y := py + 82 + float64(i)*58
		dc.SetRGBA255(255, 255, 255, 8)
		dc.DrawRoundedRectangle(rx+20, y, rw-40, 50, 12)
		dc.Fill()
		c := ghLangColor(r.Language)
		dc.SetRGB255(int(c.R), int(c.G), int(c.B))
		dc.DrawCircle(rx+44, y+25, 7)
		dc.Fill()
		dc.SetRGB255(241, 245, 249)
		dc.SetFontFace(fonts.face(true, 21))
		dc.DrawString(ghFit(dc, r.Name, 280), rx+62, y+32)
		dc.SetFontFace(fonts.face(false, 19))
		dc.SetRGBA255(250, 204, 21, 255)
		ghStar(dc, rx+rw-178, y+25, 9)
		dc.DrawStringAnchored(ghShort(r.StargazersCount), rx+rw-164, y+25, 0, 0.5)
		dc.SetRGBA255(148, 163, 184, 255)
		ghFork(dc, rx+rw-88, y+25, 9)
		dc.DrawStringAnchored(ghShort(r.ForksCount), rx+rw-74, y+25, 0, 0.5)
	}
	if len(top) == 0 {
		dc.SetRGBA255(148, 163, 184, 255)
		dc.SetFontFace(fonts.face(false, 22))
		dc.DrawStringAnchored("No public repositories yet", rx+rw/2, py+200, 0.5, 0.5)
	}

	ix, iw := 1120.0, float64(W)-70-1120
	ghPanel(dc, ix, py, iw, ph)
	dc.SetRGB255(255, 255, 255)
	dc.SetFontFace(fonts.face(true, 26))
	dc.DrawString("Activity", ix+30, py+46)
	var byDay [7]int
	best := ghContribDay{}
	for _, day := range days {
		if t, err := time.Parse("2006-01-02", day.Date); err == nil {
			byDay[t.Weekday()] += day.ContributionCount
		}
		if day.ContributionCount > best.ContributionCount {
			best = day
		}
	}
	maxDay, busiest := 1, 0
	for i, v := range byDay {
		if v > maxDay {
			maxDay, busiest = v, i
		}
	}
	barW, barGap, barBase := 34.0, 14.0, py+180
	for i, v := range byDay {
		x := ix + 36 + float64(i)*(barW+barGap)
		h := 95 * float64(v) / float64(maxDay)
		g := gg.NewLinearGradient(0, barBase-h, 0, barBase)
		g.AddColorStop(0, ghHex("#39d353"))
		g.AddColorStop(1, ghHex("#0e4429"))
		dc.SetFillStyle(g)
		dc.DrawRoundedRectangle(x, barBase-h, barW, math.Max(h, 4), 6)
		dc.Fill()
		dc.SetRGBA255(148, 163, 184, 255)
		dc.SetFontFace(fonts.face(false, 16))
		dc.DrawStringAnchored(time.Weekday(i).String()[:2], x+barW/2, barBase+18, 0.5, 0.5)
	}
	avg := 0.0
	if activeDays > 0 {
		avg = float64(d.Total) / float64(activeDays)
	}
	insights := []string{
		fmt.Sprintf("Current streak  %d days", current),
		fmt.Sprintf("Most active on  %ss", time.Weekday(busiest).String()),
		fmt.Sprintf("Active days  %d / %d", activeDays, len(days)),
		fmt.Sprintf("Avg per active day  %.1f", avg),
	}
	if best.ContributionCount > 0 {
		if t, err := time.Parse("2006-01-02", best.Date); err == nil {
			insights = append(insights, fmt.Sprintf("Best day  %d on %s", best.ContributionCount, t.Format("Jan 2")))
		}
	}
	dc.SetFontFace(fonts.face(false, 19))
	for i, s := range insights {
		parts := strings.SplitN(s, "  ", 2)
		y := py + 238 + float64(i)*27
		dc.SetRGBA255(148, 163, 184, 255)
		dc.DrawStringAnchored(parts[0], ix+30, y, 0, 0.5)
		if len(parts) == 2 {
			dc.SetRGB255(241, 245, 249)
			dc.DrawStringAnchored(parts[1], ix+iw-30, y, 1, 0.5)
		}
	}

	dc.SetRGBA255(100, 116, 139, 255)
	dc.SetFontFace(fonts.face(false, 18))
	dc.DrawStringAnchored("github.com/"+d.User.Login+"   •   generated "+time.Now().UTC().Format("02 Jan 2006"), W/2, H-26, 0.5, 0.5)
	return dc.Image(), nil
}

func GhGraphHandler(m *tg.NewMessage) error {
	user := strings.TrimPrefix(strings.TrimSpace(firstField(m.Args())), "@")
	if user == "" {
		m.Reply("Usage: <code>/ghgraph &lt;github username&gt;</code>")
		return nil
	}
	if !ghContribValidUser(user) {
		m.Reply("That isn't a valid GitHub username.")
		return nil
	}
	status := modules.NewStatus(m, "Building the GitHub graph for <code>"+html.EscapeString(user)+"</code>…")
	u, err := ghFetchUser(user)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			status.Edit("No GitHub user named <code>" + html.EscapeString(user) + "</code>.")
		} else {
			status.Edit("Couldn't reach GitHub right now (" + html.EscapeString(err.Error()) + ").")
		}
		return nil
	}
	d := &ghGraphData{User: *u}
	d.Created, _ = time.Parse(time.RFC3339, u.CreatedAt)
	done := make(chan struct{}, 3)
	go func() {
		d.Repos, _ = ghFetchAllRepos(u.Login)
		done <- struct{}{}
	}()
	go func() {
		if c, _, err := ghContribFetch(u.Login); err == nil {
			d.Days, d.Total = ghContribFlatten(c.Contributions), c.TotalContributions
		}
		done <- struct{}{}
	}()
	go func() {
		d.Avatar = ghFetchAvatar(u.AvatarURL)
		done <- struct{}{}
	}()
	for range 3 {
		<-done
	}
	img, err := renderGHGraph(d)
	if err != nil {
		status.Edit("Couldn't draw the graph: " + html.EscapeString(err.Error()))
		return nil
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		status.Edit("Couldn't encode the graph.")
		return nil
	}
	path := fmt.Sprintf("%s/ghgraph_%s_%d.png", os.TempDir(), u.Login, time.Now().UnixNano())
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		status.Edit("Couldn't save the graph.")
		return nil
	}
	defer os.Remove(path)
	caption := fmt.Sprintf("<b>%s</b> on GitHub\n<a href=\"%s\">github.com/%s</a>", html.EscapeString(ghFirstNonEmpty(u.Name, u.Login)), html.EscapeString(u.HTMLURL), html.EscapeString(u.Login))
	status.Done()
	if _, err := modules.TransferReplyMedia(m, path, &tg.MediaOptions{Caption: caption, ForceDocument: false}); err != nil {
		status.Edit("Couldn't send the graph: " + html.EscapeString(err.Error()))
	}
	return nil
}

func ghFirstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func init() {
	modules.QueueHandlerRegistration(func() {
		modules.OnCommand(modules.Client, "cmd:ghgraph", GhGraphHandler)
	})
}
