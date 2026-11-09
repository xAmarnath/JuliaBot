package modules

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
)

func TestMirrorWidgetPhaseTransition(t *testing.T) {
	v := &transferProgressView{widget: true, total: 1000, started: time.Now(), writeState: func(context.Context, string) error { return nil }}
	v.updateProgress(context.Background(), &tg.ProgressInfo{Current: 900}, 0, 1, 1, "File DC: 2", 0)
	if err := v.BeginPhase(context.Background(), "Uploading", 1000); err != nil {
		t.Fatal(err)
	}
	v.updateProgress(context.Background(), &tg.ProgressInfo{Current: 1000}, 0, 1, 1, "File DC: 2", 0)
	if v.state.Phase != "Uploading" || v.state.Percent != 0 {
		t.Fatal("stale download overwrote upload", v.state)
	}
	v.updateProgress(context.Background(), &tg.ProgressInfo{Current: 250}, 0, 1, 1, "Upload DC: 4", 1)
	if v.state.Percent != 25 || v.state.Phase != "Uploading" {
		t.Fatal(v.state)
	}
	if err := v.finishState("Completed", "Delivered"); err != nil {
		t.Fatal(err)
	}
	_ = v.BeginPhase(context.Background(), "Downloading", 500)
	if v.state.Phase != "Completed" {
		t.Fatal("completed mirror restarted")
	}
}

func TestAriaWidgetMetadataAndTotals(t *testing.T) {
	s, total := ariaWidgetState([]ariaItem{{Total: "100", Completed: "100", FollowedBy: []string{"child"}}, {Total: "1000", Completed: "250", Speed: "50", Connections: "3", Seeders: "2"}}, "magnet:?xt=urn:btih:test&dn=Example", 10*time.Second)
	if total != 1000 || s.Percent != 25 || s.Phase != "Fetching metadata" || s.Name != "Example" || s.ETA != "15s" {
		t.Fatal(s, total)
	}
	item := ariaItem{Total: "1000", Completed: "500", Speed: "0"}
	item.Bittorrent.Info.Name = "Movie"
	s, _ = ariaWidgetState([]ariaItem{item}, "magnet:?xt=x", time.Second)
	if s.Phase != "Downloading" || s.Detail == "" || s.ETA != "" {
		t.Fatal(s)
	}
	s, _ = ariaWidgetState(nil, "https://example.com/file.bin", time.Second)
	if s.Name != "file.bin" || s.Percent != 0 || s.Size != "0 B / unknown" {
		t.Fatal(s)
	}
}

func TestAriaRealHTTPAndCancellation(t *testing.T) {
	if _, err := exec.LookPath("aria2c"); err != nil {
		t.Skip("aria2c not installed")
	}
	payload := bytes.Repeat([]byte("JuliaBot aria widget verification\n"), 16000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow.bin" {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(30 * time.Second):
			}
		}
		http.ServeContent(w, r, "fixture.bin", time.Time{}, bytes.NewReader(payload))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	updates := 0
	files, err := runAriaDownload(ctx, server.URL+"/fixture.bin", t.TempDir(), func(items []ariaItem) {
		updates++
		s, _ := ariaWidgetState(items, server.URL, time.Second)
		if s.Percent < 0 || s.Percent > 100 {
			t.Error(s)
		}
	})
	if err != nil || len(files) != 1 || updates == 0 {
		t.Fatal(files, updates, err)
	}
	got, err := os.ReadFile(files[0])
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("download mismatch", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_, err = runAriaDownload(ctx2, server.URL+"/slow.bin", t.TempDir(), func([]ariaItem) {})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cancellation not propagated", err)
	}
}
