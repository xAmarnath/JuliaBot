package kisskh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/language"
)

// Keep subprocess diagnostics bounded; HLS failures can otherwise fill memory.
type tailBuffer struct {
	mu   sync.Mutex
	data []byte
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	b.data = append(b.data, p...)
	if len(b.data) > 8192 {
		b.data = bytes.Clone(b.data[len(b.data)-8192:])
	}
	return n, nil
}
func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	var out tailBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if e := cmd.Run(); e != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s failed: %w: %s", name, e, strings.TrimSpace(string(out.data)))
	}
	return nil
}
func DownloadArgs(video, dir string, maxBytes int64) []string {
	return []string{"--ignore-config", "--no-playlist", "--no-warnings", "--no-progress", "--no-simulate", "--no-check-formats", "--concurrent-fragments", "8", "--retries", "3", "--fragment-retries", "3", "--abort-on-unavailable-fragments", "--socket-timeout", "30", "--hls-prefer-native", "--user-agent", UserAgent, "--referer", "https://kisskh.is/", "--max-filesize", strconv.FormatInt(maxBytes, 10), "--remux-video", "mp4", "-o", filepath.Join(dir, "source.%(ext)s"), "--", video}
}
func MuxArgs(input, output, dir string, subs []Subtitle) []string {
	a := []string{"-nostdin", "-v", "error", "-y", "-i", input}
	for i := range subs {
		a = append(a, "-i", filepath.Join(dir, fmt.Sprintf("sub-%02d.srt", i)))
	}
	a = append(a, "-map", "0:v:0", "-map", "0:a?")
	for i, s := range subs {
		base, _ := language.Make(s.Language).Base()
		label := s.Label
		if label == "" {
			label = s.Language
		}
		a = append(a, "-map", fmt.Sprintf("%d:0", i+1), fmt.Sprintf("-metadata:s:s:%d", i), "language="+base.ISO3(), fmt.Sprintf("-metadata:s:s:%d", i), "title="+label, fmt.Sprintf("-metadata:s:s:%d", i), "handler_name="+label, fmt.Sprintf("-disposition:s:%d", i))
		if s.Default {
			a = append(a, "default")
		} else {
			a = append(a, "0")
		}
	}
	return append(a, "-c:v", "copy", "-c:a", "copy", "-c:s", "mov_text", "-movflags", "+faststart", output)
}

type Metadata struct {
	Width, Height int
	Duration      float64
	Subtitles     int
}

func Probe(ctx context.Context, path string) (Metadata, error) {
	var m Metadata
	b, e := exec.CommandContext(ctx, "ffprobe", "-v", "error", "-show_entries", "stream=codec_type,width,height,duration", "-of", "json", path).Output()
	if e != nil {
		return m, fmt.Errorf("ffprobe: %w", e)
	}
	var p struct {
		Streams []struct {
			CodecType     string `json:"codec_type"`
			Width, Height int
			Duration      string
		}
	}
	if e = json.Unmarshal(b, &p); e != nil {
		return m, e
	}
	for _, s := range p.Streams {
		if s.CodecType == "subtitle" {
			m.Subtitles++
		}
		if s.CodecType == "video" && m.Width == 0 {
			m.Width, m.Height = s.Width, s.Height
			m.Duration, _ = strconv.ParseFloat(s.Duration, 64)
		}
	}
	if m.Width <= 0 || m.Height <= 0 || m.Duration <= 0 {
		return m, fmt.Errorf("video metadata missing or invalid")
	}
	return m, nil
}
func Download(ctx context.Context, source *Source, dir, filename string, maxBytes int64, stage func(string)) (string, Metadata, error) {
	var empty Metadata
	if maxBytes <= 0 {
		return "", empty, fmt.Errorf("invalid upload size limit")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Stop downloads that outgrow the account's upload limit even when HLS
	// does not advertise a Content-Length. yt-dlp's own limit is not enough.
	monitorDone := make(chan struct{})
	oversize := make(chan struct{}, 1)
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				files, _ := filepath.Glob(filepath.Join(dir, "source*"))
				for _, f := range files {
					if st, e := os.Stat(f); e == nil && st.Size() > maxBytes {
						oversize <- struct{}{}
						cancel()
						return
					}
				}
			}
		}
	}()
	defer func() { cancel(); <-monitorDone }()
	stage("Downloading episode (8 parallel fragments)…")
	if e := run(ctx, "yt-dlp", DownloadArgs(source.Video, dir, maxBytes)...); e != nil {
		select {
		case <-oversize:
			return "", empty, fmt.Errorf("episode exceeds the Telegram account upload limit")
		default:
			return "", empty, e
		}
	}
	input := filepath.Join(dir, "source.mp4")
	if st, e := os.Stat(input); e != nil || st.Size() == 0 {
		return "", empty, fmt.Errorf("downloader did not produce a video")
	}
	for i, s := range source.Subtitles {
		if e := ValidateSubtitle(s.Text); e != nil {
			return "", empty, e
		}
		if e := os.WriteFile(filepath.Join(dir, fmt.Sprintf("sub-%02d.srt", i)), []byte(s.Text), 0600); e != nil {
			return "", empty, e
		}
	}
	stage(fmt.Sprintf("Embedding %d selectable subtitle tracks…", len(source.Subtitles)))
	output := filepath.Join(dir, filepath.Base(filename))
	if e := run(ctx, "ffmpeg", MuxArgs(input, output, dir, source.Subtitles)...); e != nil {
		return "", empty, e
	}
	st, e := os.Stat(output)
	if e != nil {
		return "", empty, e
	}
	if st.Size() > maxBytes {
		return "", empty, fmt.Errorf("video with subtitles exceeds the Telegram account upload limit")
	}
	meta, e := Probe(ctx, output)
	if e != nil {
		return "", empty, e
	}
	if meta.Subtitles != len(source.Subtitles) {
		return "", empty, fmt.Errorf("subtitle track count mismatch")
	}
	return output, meta, nil
}
func Thumbnail(ctx context.Context, video, path string) error {
	return run(ctx, "ffmpeg", "-nostdin", "-v", "error", "-y", "-ss", "1", "-i", video, "-frames:v", "1", "-vf", "scale=320:320:force_original_aspect_ratio=decrease", "-q:v", "5", path)
}
