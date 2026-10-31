package extras

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func ffprobeField(t *testing.T, path, entries string) string {
	t.Helper()
	out, err := exec.Command("ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", entries, "-of", "default=noprint_wrappers=1:nokey=1", path).Output()
	if err != nil {
		t.Fatalf("ffprobe %s: %v", entries, err)
	}
	return strings.TrimSpace(string(out))
}

func TestEncodeVideoStickerMeetsTelegramLimits(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed")
	}
	dir := t.TempDir()
	inputs := map[string][]string{
		"noisy_1080p_10s.mp4": {"-f", "lavfi", "-i", "testsrc2=size=1920x1080:rate=60:duration=10", "-f", "lavfi", "-i", "noise=alls=100:allf=t", "-vf", "noise=alls=80:allf=t+u"},
		"portrait_5s.mp4":     {"-f", "lavfi", "-i", "mandelbrot=size=720x1280:rate=30", "-t", "5"},
		"short.gif":           {"-f", "lavfi", "-i", "testsrc=size=320x240:rate=15:duration=1.5"},
		"with_audio.mp4":      {"-f", "lavfi", "-i", "testsrc=size=640x360:rate=25:duration=4", "-f", "lavfi", "-i", "sine=duration=4"},
	}
	for name, args := range inputs {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join(dir, name)
			cmd := append([]string{"-y", "-loglevel", "error"}, args...)
			if name == "noisy_1080p_10s.mp4" {
				cmd = []string{"-y", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc2=size=1920x1080:rate=60:duration=10", "-vf", "noise=alls=80:allf=t+u"}
			}
			cmd = append(cmd, src)
			if out, err := exec.Command("ffmpeg", cmd...).CombinedOutput(); err != nil {
				t.Fatalf("make input: %v %s", err, out)
			}
			dst := filepath.Join(dir, name+".webm")
			if err := encodeVideoSticker(src, dst); err != nil {
				t.Fatalf("encode: %v", err)
			}
			st, _ := os.Stat(dst)
			if st.Size() > videoStickerMaxBytes {
				t.Fatalf("size %d KB > 256 KB", st.Size()/1024)
			}
			if c := ffprobeField(t, dst, "stream=codec_name"); c != "vp9" {
				t.Fatalf("codec %s", c)
			}
			w, _ := strconv.Atoi(ffprobeField(t, dst, "stream=width"))
			h, _ := strconv.Atoi(ffprobeField(t, dst, "stream=height"))
			if !(w <= 512 && h <= 512 && (w == 512 || h == 512)) {
				t.Fatalf("dimensions %dx%d", w, h)
			}
			if d := probeDuration(dst); d > 3.0 || d <= 0 {
				t.Fatalf("duration %.2fs", d)
			}
			var num, den int
			fmt.Sscanf(ffprobeField(t, dst, "stream=avg_frame_rate"), "%d/%d", &num, &den)
			if den > 0 && float64(num)/float64(den) > 30.01 {
				t.Fatalf("fps %d/%d", num, den)
			}
			if a, _ := exec.Command("ffprobe", "-v", "error", "-select_streams", "a", "-show_entries", "stream=index", "-of", "csv=p=0", dst).Output(); strings.TrimSpace(string(a)) != "" {
				t.Fatal("audio stream present")
			}
			t.Logf("%s -> %dx%d %.2fs %d KB", name, w, h, probeDuration(dst), st.Size()/1024)
		})
	}
}
