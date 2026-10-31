package kisskh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"

var ErrNotReleased = errors.New("episode has not been released yet")

type Episode struct {
	Sub      int     `json:"sub"`
	Released bool    `json:"released,omitempty"`
	ID       int64   `json:"id"`
	Number   float64 `json:"number"`
}
type Drama struct {
	Thumbnail   string    `json:"thumbnail"`
	ID          int64     `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	Episodes    []Episode `json:"episodes"`
}
type Subtitle struct {
	URL      string `json:"src"`
	Label    string `json:"label"`
	Language string `json:"land"`
	Default  bool   `json:"default"`
	Text     string `json:"-"`
}
type Source struct {
	Video     string
	Subtitles []Subtitle
}
type Client struct {
	Base, Crypto string
	HTTP         *http.Client
}

func New() *Client {
	return &Client{"https://kisskh.is", "https://enc-dec.app/api", &http.Client{Timeout: 45 * time.Second}}
}

func DramaID(input string) (int64, bool) {
	input = strings.TrimSpace(input)
	if u, err := url.Parse(input); err == nil && (u.Hostname() == "kisskh.is" || u.Hostname() == "kisskh.do") {
		input = u.Query().Get("id")
	}
	id, err := strconv.ParseInt(input, 10, 64)
	return id, err == nil && id > 0
}
func (c *Client) get(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", c.Base+"/")
	req.Header.Set("Cache-Control", "no-cache")
	r, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("KissKH request failed: %w", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KissKH service returned HTTP %d", r.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024+1))
	if len(b) > 4*1024*1024 {
		return nil, fmt.Errorf("KissKH response too large")
	}
	return b, err
}
func (c *Client) Search(ctx context.Context, query string) ([]Drama, error) {
	b, e := c.get(ctx, c.Base+"/api/DramaList/Search?"+url.Values{"q": {query}, "type": {"0"}}.Encode())
	if e != nil {
		return nil, e
	}
	var list []Drama
	e = json.Unmarshal(b, &list)
	return list, e
}
func (c *Client) Drama(ctx context.Context, id int64) (*Drama, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid drama ID")
	}
	b, e := c.get(ctx, fmt.Sprintf("%s/api/DramaList/Drama/%d?isq=true", c.Base, id))
	if e != nil {
		return nil, e
	}
	var d Drama
	if e = json.Unmarshal(b, &d); e != nil {
		return nil, e
	}
	if d.Title == "" {
		return nil, fmt.Errorf("drama not found")
	}
	d.ID = id
	sort.Slice(d.Episodes, func(i, j int) bool { return d.Episodes[i].Number < d.Episodes[j].Number })
	return &d, nil
}
func (c *Client) key(ctx context.Context, id int64, kind string) (string, error) {
	b, e := c.get(ctx, c.Crypto+"/enc-kisskh?"+url.Values{"text": {strconv.FormatInt(id, 10)}, "type": {kind}, "_": {strconv.FormatInt(time.Now().UnixNano(), 10)}}.Encode())
	if e != nil {
		return "", e
	}
	var v struct {
		Status int
		Result string
	}
	if e = json.Unmarshal(b, &v); e != nil {
		return "", e
	}
	if v.Status != 200 || v.Result == "" {
		return "", fmt.Errorf("KissKH key service rejected %s request (status %d)", kind, v.Status)
	}
	return v.Result, nil
}
func HTTPURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil
}

var cuePattern = regexp.MustCompile(`(?m)^(\d{2,}:\d{2}:\d{2}[,.]\d{3})\s*-->\s*(\d{2,}:\d{2}:\d{2}[,.]\d{3})`)

func ValidateSubtitle(text string) error {
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) || len(cuePattern.FindAllString(text, -1)) == 0 {
		return fmt.Errorf("decryption did not return valid UTF-8 SRT subtitles")
	}
	return nil
}

func (c *Client) video(ctx context.Context, id int64) (string, error) {
	var responseType any
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", ctx.Err()
			case <-timer.C:
			}
		}
		key, err := c.key(ctx, id, "vid")
		if err != nil {
			return "", err
		}
		b, err := c.get(ctx, fmt.Sprintf("%s/api/DramaList/Episode/%d.png?", c.Base, id)+url.Values{"err": {"false"}, "ts": {""}, "time": {""}, "kkey": {key}, "_": {strconv.FormatInt(time.Now().UnixNano(), 10)}}.Encode())
		if err != nil {
			return "", err
		}
		var v struct {
			Video     string
			Temporary string `json:"Video_tmp"`
			Type      any
		}
		if err = json.Unmarshal(b, &v); err != nil {
			return "", fmt.Errorf("invalid episode response: %w", err)
		}
		responseType = v.Type
		if fmt.Sprint(v.Type) == "2" || strings.Contains(v.Video, "tickcounter.com/") {
			return "", ErrNotReleased
		}
		for _, candidate := range []string{v.Video, v.Temporary} {
			candidate = strings.TrimSpace(candidate)
			if strings.HasPrefix(candidate, "//") {
				candidate = "https:" + candidate
			}
			if HTTPURL(candidate) {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("KissKH returned no video for episode %d after 3 fresh-key attempts (response type %v). Please retry shortly", id, responseType)
}
func (c *Client) Resolve(ctx context.Context, id int64) (*Source, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid episode ID")
	}
	video, e := c.video(ctx, id)
	if e != nil {
		return nil, e
	}
	sk, e := c.key(ctx, id, "sub")
	if e != nil {
		return nil, e
	}
	b, e := c.get(ctx, fmt.Sprintf("%s/api/Sub/%d?", c.Base, id)+url.Values{"kkey": {sk}}.Encode())
	if e != nil {
		return nil, e
	}
	s := &Source{Video: video}
	if e = json.Unmarshal(b, &s.Subtitles); e != nil {
		return nil, e
	}
	if len(s.Subtitles) > 64 {
		return nil, fmt.Errorf("too many subtitle tracks")
	}
	for i := range s.Subtitles {
		sub := &s.Subtitles[i]
		if !HTTPURL(sub.URL) {
			return nil, fmt.Errorf("invalid subtitle URL for %s", sub.Label)
		}
		b, e = c.get(ctx, c.Crypto+"/dec-kisskh?"+url.Values{"url": {sub.URL}}.Encode())
		if e != nil {
			return nil, fmt.Errorf("%s subtitles: %w", sub.Label, e)
		}
		sub.Text = strings.TrimPrefix(string(b), "\ufeff")
		if e = ValidateSubtitle(sub.Text); e != nil {
			return nil, fmt.Errorf("%s subtitles: %w", sub.Label, e)
		}
	}
	return s, nil
}
