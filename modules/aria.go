package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
)

type ariaRPC struct {
	url, secret string
	client      *http.Client
}

func (a *ariaRPC) call(ctx context.Context, method string, params []any, result any) error {
	params = append([]any{"token:" + a.secret}, params...)
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "jb", "method": "aria2." + method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("aria2 RPC returned HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&envelope); err != nil {
		return err
	}
	if envelope.Error != nil {
		return errors.New(envelope.Error.Message)
	}
	return json.Unmarshal(envelope.Result, result)
}

type ariaItem struct {
	GID         string   `json:"gid"`
	Status      string   `json:"status"`
	Total       string   `json:"totalLength"`
	Completed   string   `json:"completedLength"`
	Speed       string   `json:"downloadSpeed"`
	Error       string   `json:"errorMessage"`
	FollowedBy  []string `json:"followedBy"`
	Connections string   `json:"connections"`
	Seeders     string   `json:"numSeeders"`
	Bittorrent  struct {
		Info struct {
			Name string `json:"name"`
		} `json:"info"`
	} `json:"bittorrent"`
	Files []struct {
		Path string `json:"path"`
	} `json:"files"`
}

type ariaOutput struct {
	mu   sync.Mutex
	tail []byte
}

func (b *ariaOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if len(p) > 8192 {
		p = p[len(p)-8192:]
	}
	b.tail = append(b.tail, p...)
	if len(b.tail) > 8192 {
		b.tail = append([]byte(nil), b.tail[len(b.tail)-8192:]...)
	}
	return n, nil
}
func (b *ariaOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(string(b.tail))
}

func ariaProgressText(items []ariaItem, uri string, elapsed time.Duration) string {
	total, current, speed, _, _ := ariaTotals(items)
	name := ""
	var connections, seeders int64
	metadataReady := false
	for _, item := range items {
		if len(item.FollowedBy) > 0 {
			continue
		}
		if item.Bittorrent.Info.Name != "" {
			name = item.Bittorrent.Info.Name
			metadataReady = true
		}
		if name == "" && len(item.Files) > 0 && !strings.HasPrefix(item.Files[0].Path, "[MEMORY]") {
			name = filepath.Base(item.Files[0].Path)
		}
		n, _ := strconv.ParseInt(item.Connections, 10, 64)
		connections += n
		n, _ = strconv.ParseInt(item.Seeders, 10, 64)
		seeders += n
	}
	u, _ := url.Parse(uri)
	magnet := u != nil && strings.EqualFold(u.Scheme, "magnet")
	if name == "" && u != nil {
		name = u.Query().Get("dn")
		if name == "" && !magnet {
			name = filepath.Base(u.Path)
		}
	}
	if name == "" || name == "." {
		name = "Waiting for file name"
	}
	runes := []rune(name)
	if len(runes) > 200 {
		name = string(runes[:200]) + "…"
	}
	pct := float64(0)
	if total > 0 {
		pct = 100 * float64(current) / float64(total)
	}
	text := fmt.Sprintf("<b>aria2 download</b>\n<b>Name:</b> %s\n%.2f / %.2f MiB · %.2f%%\n<b>Speed:</b> %.2f MiB/s\n<b>Elapsed:</b> %s", transferCaption(name), float64(current)/(1<<20), float64(total)/(1<<20), pct, float64(speed)/(1<<20), elapsed.Round(time.Second))
	if magnet {
		text += fmt.Sprintf("\n<b>Connections:</b> %d | <b>Seeders:</b> %d", connections, seeders)
		if !metadataReady {
			text += "\nFetching torrent metadata…"
		} else if speed == 0 && current < total {
			if connections == 0 {
				text += "\nLooking for peers that can send this file…"
			} else {
				text += "\nPeers connected; waiting for file data…"
			}
		}
	}
	return text
}

func ariaSource(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid download URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		if u.Host != "" {
			return raw, nil
		}
	case "magnet":
		if u.Query().Get("xt") != "" {
			return raw, nil
		}
	}
	return "", errors.New("use an HTTP(S) URL or a magnet link")
}

func ariaTotals(items []ariaItem) (int64, int64, int64, []string, error) {
	var total, complete, speed int64
	var files []string
	for _, item := range items {
		if len(item.FollowedBy) > 0 {
			continue
		}
		n, _ := strconv.ParseInt(item.Total, 10, 64)
		total += n
		n, _ = strconv.ParseInt(item.Completed, 10, 64)
		complete += n
		n, _ = strconv.ParseInt(item.Speed, 10, 64)
		speed += n
		if item.Status == "error" {
			return total, complete, speed, nil, fmt.Errorf("aria2: %s", item.Error)
		}
		if item.Status == "complete" {
			for _, f := range item.Files {
				files = append(files, f.Path)
			}
		}
	}
	return total, complete, speed, files, nil
}

func runAriaDownload(ctx context.Context, uri, dir string, progress func([]ariaItem)) ([]string, error) {
	binary, err := exec.LookPath("aria2c")
	if err != nil {
		return nil, errors.New("aria2c is not installed")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	secret := transferToken()
	config := filepath.Join(dir, ".aria-rpc.conf")
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = filepath.Dir(dir)
	}
	cacheDir = filepath.Join(cacheDir, "juliabot-aria")
	if err = os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, err
	}
	dhtPath := filepath.Join(dir, ".aria-dht.dat")
	if cached, e := os.ReadFile(filepath.Join(cacheDir, "dht.dat")); e == nil {
		_ = os.WriteFile(dhtPath, cached, 0600)
	}
	defer func() {
		if data, e := os.ReadFile(dhtPath); e == nil && len(data) > 0 {
			if tmp, e := os.CreateTemp(cacheDir, "dht-*"); e == nil {
				name := tmp.Name()
				_, e = tmp.Write(data)
				closeErr := tmp.Close()
				if e == nil && closeErr == nil {
					_ = os.Rename(name, filepath.Join(cacheDir, "dht.dat"))
				}
				_ = os.Remove(name)
			}
		}
		_ = os.Remove(dhtPath)
	}()
	settings := fmt.Sprintf("enable-rpc=true\nrpc-listen-all=false\nrpc-listen-port=%d\nrpc-secret=%s\nseed-time=0\nfile-allocation=none\nallow-overwrite=false\nauto-file-renaming=true\nconsole-log-level=error\nsummary-interval=0\nmax-connection-per-server=8\nsplit=8\n", port, secret)
	settings += "dht-file-path=" + dhtPath + "\ndht-entry-point=router.bittorrent.com:6881\n"
	if err = os.WriteFile(config, []byte(settings), 0600); err != nil {
		return nil, err
	}
	defer os.Remove(config)
	processCtx, kill := context.WithCancel(context.Background())
	defer kill()
	cmd := exec.CommandContext(processCtx, binary, "--conf-path="+config)
	output := &ariaOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait(); close(exited) }()
	rpc := &ariaRPC{url: fmt.Sprintf("http://127.0.0.1:%d/jsonrpc", port), secret: secret, client: &http.Client{Timeout: 3 * time.Second}}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
		var response string
		_ = rpc.call(shutdown, "shutdown", nil, &response)
		cancel()
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
			kill()
			<-exited
		}
	}()
	ready, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		var version any
		if err = rpc.call(ready, "getVersion", nil, &version); err == nil {
			break
		}
		select {
		case <-ready.Done():
			return nil, fmt.Errorf("aria2 startup: %w", ready.Err())
		case processErr := <-exited:
			return nil, fmt.Errorf("aria2 stopped during startup: %v; %s", processErr, output.String())
		case <-time.After(150 * time.Millisecond):
		}
	}
	var gid string
	if err = rpc.call(ctx, "addUri", []any{[]string{uri}, map[string]string{"dir": dir, "seed-time": "0"}}, &gid); err != nil {
		return nil, err
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case processErr := <-exited:
			return nil, fmt.Errorf("aria2 stopped before completion: %v; %s", processErr, output.String())
		case <-ticker.C:
		}
		var active, waiting, stopped []ariaItem
		err = rpc.call(ctx, "tellActive", nil, &active)
		if err == nil {
			err = rpc.call(ctx, "tellWaiting", []any{0, 1000}, &waiting)
		}
		if err == nil {
			err = rpc.call(ctx, "tellStopped", []any{0, 1000}, &stopped)
		}
		if err != nil {
			failures++
			if failures >= 3 {
				return nil, fmt.Errorf("aria2 progress: %w", err)
			}
			continue
		}
		failures = 0
		items := append(append(active, waiting...), stopped...)
		_, _, _, files, err := ariaTotals(items)
		if err != nil {
			return nil, err
		}
		progress(items)
		if len(active) == 0 && len(waiting) == 0 && len(files) > 0 {
			return files, nil
		}
	}
}

func AriaDownloadHandle(m *tg.NewMessage) error {
	uri, err := ariaSource(m.Args())
	if err != nil {
		_, err = m.Reply("Usage: <code>/ariadl https://…</code> or <code>/ariadl magnet:?xt=…</code>")
		return err
	}
	if err = os.MkdirAll("downloads", 0755); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("downloads", "aria-")
	if err != nil {
		return err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		if !completed {
			_ = os.RemoveAll(dir)
		}
	}()
	view, err := newTransferProgress(m, "Starting aria2", "Waiting for file name", 0)
	if err != nil {
		return err
	}
	status := view.status
	ctx, done := TrackFileTransfer(status, m.SenderID())
	defer done()
	started := time.Now()
	last := time.Time{}
	files, err := runAriaDownload(ctx, uri, dir, func(items []ariaItem) {
		if view.widget {
			view.updateAria(ctx, items, uri)
			return
		}
		if time.Since(last) < 5*time.Second || ctx.Err() != nil {
			return
		}
		last = time.Now()
		text := ariaProgressText(items, uri, time.Since(started))
		_, _ = status.Edit(text, &tg.SendOptions{ParseMode: tg.HTML, ReplyMarkup: transferCancelKeyboard(status.ID)})
	})
	if err != nil {
		text := "aria2 download failed: " + html.EscapeString(err.Error())
		detail := err.Error()
		if errors.Is(err, context.Canceled) {
			text = "aria2 download cancelled. Partial files removed."
			detail = "Partial files removed."
		}
		phase := "Failed"
		if errors.Is(err, context.Canceled) {
			phase = "Cancelled"
		}
		return view.Finish(phase, detail, text)
	}
	completed = true
	var out strings.Builder
	out.WriteString("<b>Download complete</b>\n")
	for _, file := range files[:min(len(files), 12)] {
		cwd, _ := os.Getwd()
		if relative, e := filepath.Rel(cwd, file); e == nil {
			file = relative
		}
		out.WriteString(transferCaption(file) + "\n")
	}
	if len(files) > 12 {
		fmt.Fprintf(&out, "…and %d more files.\n", len(files)-12)
	}
	out.WriteString("Use <code>/ul path</code> to upload a file.")
	return view.Finish("Completed", fmt.Sprintf("%d file(s) saved. Use /ul with a path below to upload.", len(files)), out.String())
}

func ariaWidgetState(items []ariaItem, uri string, elapsed time.Duration) (transferWidgetState, int64) {
	total, current, speed, _, _ := ariaTotals(items)
	s := transferWidgetState{Phase: "Downloading", Elapsed: elapsed.Round(time.Second).String()}
	u, _ := url.Parse(uri)
	magnet := u != nil && strings.EqualFold(u.Scheme, "magnet")
	var connections, seeders int64
	metadata := false
	for _, item := range items {
		if len(item.FollowedBy) > 0 {
			continue
		}
		if item.Bittorrent.Info.Name != "" {
			s.Name = item.Bittorrent.Info.Name
			metadata = true
		}
		if s.Name == "" && len(item.Files) > 0 && !strings.HasPrefix(item.Files[0].Path, "[MEMORY]") {
			s.Name = filepath.Base(item.Files[0].Path)
		}
		n, _ := strconv.ParseInt(item.Connections, 10, 64)
		connections += n
		n, _ = strconv.ParseInt(item.Seeders, 10, 64)
		seeders += n
	}
	if s.Name == "" && u != nil {
		s.Name = u.Query().Get("dn")
		if s.Name == "" && !magnet {
			s.Name = filepath.Base(u.Path)
		}
	}
	if s.Name == "" || s.Name == "." {
		s.Name = "Waiting for file name"
	}
	s.Size = HumanBytes(uint64(max(0, current))) + " / " + HumanBytes(uint64(max(0, total)))
	if total > 0 {
		s.Percent = int(min(100.0, 100*float64(current)/float64(total)))
	} else {
		s.Size = HumanBytes(uint64(max(0, current))) + " / unknown"
	}
	s.Speed = HumanBytes(uint64(max(0, speed))) + "/s"
	if speed > 0 && total > current {
		s.ETA = (time.Duration((total-current)/speed) * time.Second).String()
	}
	if magnet {
		s.DC = fmt.Sprintf("%d connections · %d seeders", connections, seeders)
		if !metadata {
			s.Phase = "Fetching metadata"
			s.Detail = "Connecting to the torrent network…"
		} else if speed == 0 && current < total {
			s.Detail = "Waiting for peers to send file data…"
		}
	}
	return s, total
}

func (v *transferProgressView) updateAria(ctx context.Context, items []ariaItem, uri string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state.Done || ctx.Err() != nil {
		return
	}
	v.state, v.total = ariaWidgetState(items, uri, time.Since(v.started))
	if time.Now().Before(v.nextEdit) {
		return
	}
	v.nextEdit = time.Now().Add(5 * time.Second)
	editCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := v.writeState(editCtx, v.state.JSON()); err != nil {
		if wait := tg.GetFloodWait(err); wait > 0 {
			v.nextEdit = time.Now().Add(time.Duration(wait)*time.Second + time.Second)
		}
	}
}
