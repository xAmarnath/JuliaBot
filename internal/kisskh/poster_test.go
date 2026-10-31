package kisskh

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPosterThumbnailFitsTelegram(t *testing.T) {
	if _, e := exec.LookPath("ffmpeg"); e != nil {
		t.Skip("ffmpeg unavailable")
	}
	var data bytes.Buffer
	_ = png.Encode(&data, image.NewRGBA(image.Rect(0, 0, 600, 900)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data.Bytes()) }))
	defer server.Close()
	c := New()
	out := filepath.Join(t.TempDir(), "thumb.jpg")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if e := c.PosterThumbnail(ctx, server.URL, out); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(out)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	size, format, e := image.DecodeConfig(f)
	if e != nil || format != "jpeg" || size.Height != 320 || size.Width > 320 {
		t.Fatal(size, format, e)
	}
	stat, _ := f.Stat()
	if stat.Size() > 200*1024 {
		t.Fatal("thumbnail too large")
	}
}
func TestPosterRejectsNonImage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("not an image")) }))
	defer server.Close()
	if e := New().PosterThumbnail(context.Background(), server.URL, filepath.Join(t.TempDir(), "x.jpg")); e == nil {
		t.Fatal("accepted malformed image")
	}
}
