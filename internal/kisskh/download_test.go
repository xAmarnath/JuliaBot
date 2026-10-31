package kisskh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalHLSDownloadAndSoftSubtitles(t *testing.T) {
	for _, tool := range []string{"ffmpeg", "ffprobe", "yt-dlp"} {
		if _, e := exec.LookPath(tool); e != nil {
			t.Skip(tool + " unavailable")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	origin := t.TempDir()
	dir := t.TempDir()
	if e := run(ctx, "ffmpeg", "-nostdin", "-v", "error", "-f", "lavfi", "-i", "color=c=black:s=160x90:r=5", "-f", "lavfi", "-i", "sine=frequency=440", "-t", "2", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-f", "hls", "-hls_time", "1", "-hls_list_size", "0", "-hls_flags", "single_file", filepath.Join(origin, "index.m3u8")); e != nil {
		t.Fatal(e)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(origin)))
	defer srv.Close()
	source := &Source{Video: srv.URL + "/index.m3u8", Subtitles: []Subtitle{{Language: "en", Label: "English", Default: true, Text: sampleSRT}, {Language: "ar", Label: "Arabic", Text: strings.ReplaceAll(sampleSRT, "Hello world", "مرحبا")}}}
	file, meta, e := Download(ctx, source, dir, "Test E12.mp4", 2*1024*1024, func(string) {})
	if e != nil {
		t.Fatal(e)
	}
	if meta.Width != 160 || meta.Height != 90 || meta.Subtitles != 2 || meta.Duration < 1 {
		t.Fatal(meta)
	}
	if e = run(ctx, "ffmpeg", "-v", "error", "-i", file, "-frames:v", "2", "-an", "-sn", "-f", "null", "-"); e != nil {
		t.Fatal("video cannot decode", e)
	}
	b, e := exec.CommandContext(ctx, "ffmpeg", "-v", "error", "-i", file, "-map", "0:s:1", "-f", "srt", "-").Output()
	if e != nil || !strings.Contains(string(b), "مرحبا") {
		t.Fatal("Arabic subtitle did not survive mux", e, string(b))
	}
	thumb := filepath.Join(dir, "thumb.jpg")
	if e = Thumbnail(ctx, file, thumb); e != nil {
		t.Fatal(e)
	}
	if st, e := os.Stat(thumb); e != nil || st.Size() == 0 {
		t.Fatal("thumbnail missing", e)
	}
}
func TestMuxPreservesAllTracks(t *testing.T) {
	subs := []Subtitle{{Language: "en", Label: "English", Default: true}, {Language: "id"}, {Language: "ms"}, {Language: "ar"}, {Language: "km"}, {Language: "hi"}}
	args := strings.Join(MuxArgs("in.mp4", "out.mp4", "subs", subs), " ")
	for _, s := range []string{"language=eng", "language=ind", "language=msa", "language=ara", "language=khm", "language=hin", "-map 6:0", "-c:s mov_text", "-c:v copy"} {
		if !strings.Contains(args, s) {
			t.Fatal(s)
		}
	}
	if strings.Contains(args, "-shortest") || strings.Contains(args, "-vf") {
		t.Fatal("video would be shortened or burned in")
	}
}
