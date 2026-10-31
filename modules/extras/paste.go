package extras

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	modules "main/modules"

	tg "github.com/xAmarnath/gogram/telegram"
)

const pasteMaxDocBytes int64 = 2 << 20

type pasteService struct {
	id     string
	name   string
	upload func(context.Context, string) (string, error)
}

// katb.in sits behind Cloudflare, which rejects Heroku's IP range, so it is tried last.
var pasteServices = []pasteService{
	{id: "spacebin", name: "spaceb.in", upload: pasteUploadSpacebin},
	{id: "dpaste", name: "dpaste.com", upload: pasteUploadDpaste},
	{id: "pastesdev", name: "pastes.dev", upload: pasteUploadPastesDev},
	{id: "pasters", name: "paste.rs", upload: pasteUploadPasteRs},
	{id: "katbin", name: "katb.in", upload: pasteUploadKatbin},
}

const pasteUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"

var pasteClient = &http.Client{Timeout: 15 * time.Second}

var pasteNoRedirectClient = &http.Client{
	Timeout:       15 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func pasteHTTPClient() *http.Client {
	return pasteClient
}

func pasteDo(client *http.Client, req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", pasteUserAgent)
	return client.Do(req)
}

func pasteUploadPastesDev(ctx context.Context, content string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.pastes.dev/post", strings.NewReader(content))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp, err := pasteDo(pasteClient, req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pastes.dev HTTP %d", resp.StatusCode)
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out); err != nil {
		return "", err
	}
	if out.Key == "" {
		return "", fmt.Errorf("pastes.dev: empty key")
	}
	return pasteValidatedURL("https://pastes.dev/"+url.PathEscape(out.Key), "pastes.dev")
}

func pasteUploadPasteRs(ctx context.Context, content string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://paste.rs/", strings.NewReader(content))
	if err != nil {
		return "", err
	}
	resp, err := pasteDo(pasteClient, req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	// 206 means paste.rs truncated the upload; the link would not hold the full text
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("paste.rs HTTP %d", resp.StatusCode)
	}
	return pasteValidatedURL(strings.TrimSpace(string(b)), "paste.rs")
}

func pasteUploadKatbin(ctx context.Context, content string) (string, error) {
	body, err := json.Marshal(map[string]map[string]string{
		"paste": {"content": content},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://katb.in/api/paste", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := pasteDo(pasteClient, req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("katb.in HTTP %d", resp.StatusCode)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("katb.in: empty id")
	}
	return pasteValidatedURL("https://katb.in/"+url.PathEscape(out.ID), "katb.in")
}

func pasteUploadSpacebin(ctx context.Context, content string) (string, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("content", content); err != nil {
		return "", err
	}
	w.Close()
	req, err := http.NewRequestWithContext(ctx, "POST", "https://spaceb.in/", &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := pasteDo(pasteNoRedirectClient, req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && (resp.StatusCode < 300 || resp.StatusCode > 399) {
		return "", fmt.Errorf("spaceb.in HTTP %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("spaceb.in: no Location (HTTP %d)", resp.StatusCode)
	}
	if strings.HasPrefix(loc, "/") {
		loc = "https://spaceb.in" + loc
	}
	return pasteValidatedURL(loc, "spaceb.in")
}

func pasteUploadDpaste(ctx context.Context, content string) (string, error) {
	form := url.Values{
		"content":     {content},
		"syntax":      {"text"},
		"expiry_days": {"7"},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://dpaste.com/api/v2/", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := pasteDo(pasteClient, req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return "", fmt.Errorf("dpaste HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		return pasteValidatedURL(loc, "dpaste.com")
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	u := strings.TrimSpace(string(b))
	return pasteValidatedURL(u, "dpaste.com")
}

func pasteValidatedURL(raw, host string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, host) || u.User != nil || len(strings.Trim(u.Path, "/")) == 0 {
		return "", fmt.Errorf("%s returned an invalid paste URL", host)
	}
	return u.String(), nil
}

func pasteRawURL(link, service string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	key := strings.Trim(u.Path, "/")
	switch service {
	case "dpaste":
		return strings.TrimRight(link, "/") + ".txt"
	case "spacebin":
		return "https://spaceb.in/api/" + key + "/raw"
	case "pastesdev":
		return "https://api.pastes.dev/" + key
	case "pasters":
		return link
	case "katbin":
		return "https://katb.in/" + key + "/raw"
	}
	return ""
}

func pasteParseFlag(args string) (string, string) {
	args = strings.TrimSpace(args)
	for _, flag := range [][2]string{
		{"-s", "spacebin"},
		{"-d", "dpaste"},
		{"-p", "pastesdev"},
		{"-r", "pasters"},
		{"-k", "katbin"},
	} {
		if strings.HasPrefix(args, flag[0]+" ") {
			return flag[1], strings.TrimSpace(args[len(flag[0]):])
		}
		if args == flag[0] {
			return flag[1], ""
		}
	}
	return "", args
}

func pasteOrderedServices(preferredID string) []pasteService {
	if preferredID == "" {
		return pasteServices
	}
	out := make([]pasteService, 0, len(pasteServices))
	for _, s := range pasteServices {
		if s.id == preferredID {
			out = append(out, s)
			break
		}
	}
	for _, s := range pasteServices {
		if s.id != preferredID {
			out = append(out, s)
		}
	}
	return out
}

func PasteHandler(m *tg.NewMessage) error {
	preferred, rest := pasteParseFlag(m.Args())
	content := rest
	fromFile := false

	if content == "" && m.IsReply() {
		r, err := m.GetReplyMessage()
		if err != nil || r == nil {
			_, err = m.Reply("Could not read the replied message. Please reply to a text message or text file.")
			return err
		}
		if err == nil && r != nil {
			if doc := r.Document(); doc != nil {
				text, extractErr := pasteExtractDocumentText(m, doc)
				if extractErr != nil {
					m.Reply("cannot paste this file: " + html.EscapeString(extractErr.Error()))
					return nil
				}
				content = text
				fromFile = true
			} else {
				content = r.Text()
			}
		}
	}

	if strings.TrimSpace(content) == "" {
		m.Reply(pasteHelp)
		return nil
	}

	if !fromFile && int64(len(content)) > pasteMaxDocBytes {
		_, err := m.Reply("Paste too large. The limit is 2 MiB.")
		return err
	}
	status, err := m.Reply("Uploading paste…")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	services := pasteOrderedServices(preferred)
	var errs []string
	for _, svc := range services {
		urlStr, err := svc.upload(ctx, content)
		if err == nil && urlStr != "" {
			msg := "paste: " + html.EscapeString(urlStr) + "\n<i>via " + svc.name + "</i>"
			keyboard := tg.NewKeyboard().AddRow(tg.Button.URL("Open paste", urlStr))
			if raw := pasteRawURL(urlStr, svc.id); raw != "" {
				keyboard.AddRow(tg.Button.URL("Raw text", raw))
			}
			if svc.id == "dpaste" {
				msg += "\n<i>Expires in 7 days</i>"
			}
			_, err = status.Edit(msg, &tg.SendOptions{ParseMode: tg.HTML, ReplyMarkup: keyboard.Build()})
			return err
		}
		errs = append(errs, svc.name+": "+truncErr(err))
	}

	m.Client.Log.Warn("Paste services failed: %s", strings.Join(errs, "; "))
	_, err = modules.TransferUploadEdit(status, []byte(content), &tg.MediaOptions{FileName: "paste.txt", ForceDocument: true,
		Caption: "Paste services are unavailable. Your text is attached as a file."})
	if err != nil {
		_, editErr := status.Edit("Paste services are unavailable and the file could not be sent. Please try again shortly.")
		return editErr
	}
	return nil
}

func truncErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

func pasteExtractDocumentText(m *tg.NewMessage, doc *tg.DocumentObj) (string, error) {
	if doc.Size > pasteMaxDocBytes {
		return "", fmt.Errorf("file too large (max %d KB)", pasteMaxDocBytes/1024)
	}

	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if _, err := modules.TransferDownloadMedia(m.Client, doc, &tg.DownloadOptions{Ctx: ctx, Buffer: &buf}); err != nil {
		return "", fmt.Errorf("failed to download file")
	}
	return pasteDecodeText(buf.Bytes())
}

func pasteDecodeText(data []byte) (string, error) {
	if int64(len(data)) > pasteMaxDocBytes {
		return "", fmt.Errorf("file too large (max %d KB)", pasteMaxDocBytes/1024)
	}
	original := data
	binaryText := func() string { return "Binary file (base64):\n" + base64.StdEncoding.EncodeToString(original) }
	if len(data) >= 2 && (bytes.Equal(data[:2], []byte{0xff, 0xfe}) || bytes.Equal(data[:2], []byte{0xfe, 0xff})) {
		var order binary.ByteOrder = binary.LittleEndian
		if data[0] == 0xfe {
			order = binary.BigEndian
		}
		data = data[2:]
		if len(data)%2 != 0 {
			return binaryText(), nil
		}
		units := make([]uint16, len(data)/2)
		for i := range units {
			units[i] = order.Uint16(data[i*2:])
		}
		data = []byte(string(utf16.Decode(units)))
	} else {
		data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return binaryText(), nil
	}
	return string(data), nil
}

const pasteHelp = "<b>Paste</b>\n\n" +
	"<code>/paste &lt;text&gt;</code> — upload text and get a link\n" +
	"<code>/paste</code> (reply) — paste the replied message or text file (up to 2 MiB)\n\n" +
	"<b>Choose a service</b> (falls back to the others if it fails):\n" +
	"<code>-s</code> spaceb.in (default)\n" +
	"<code>-d</code> dpaste.com (expires in 7 days)\n" +
	"<code>-p</code> pastes.dev\n" +
	"<code>-r</code> paste.rs\n" +
	"<code>-k</code> katb.in\n\n" +
	"Example: <code>/paste -d some log output</code>"

func init() {
	modules.QueueHandlerRegistration(func() {
		c := modules.Client
		modules.OnCommand(c, "cmd:paste", PasteHandler)
	})
	modules.Mods.AddModule("Paste", pasteHelp)
}
