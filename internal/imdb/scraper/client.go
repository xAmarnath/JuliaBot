package scraper

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"

	fhttp "github.com/bogdanfinn/fhttp"

	"main/internal/imdb/httpx"
	"main/internal/imdb/waf"
)

const (
	baseURL          = "https://www.imdb.com"
	imdbUserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	wafTTL           = 30 * time.Minute
	wafPoolSize      = 3
	wafRefreshFactor = 0.8
	fetchTimeout     = 40 * time.Second
	challengeMarker1 = "Human Verification"
	challengeMarker2 = "awsWafCookie"
	negSentinel      = "__NEG__"
)

type Scraper struct {
	client httpx.Client

	poolMu    sync.Mutex
	pool      []wafEntry
	refreshCh chan struct{}
	stopCh    chan struct{}

	SearchCache     *cache.Cache
	DetailsCache    *cache.Cache
	DetailsNegCache *cache.Cache
	SearchNegCache  *cache.Cache
	RecsCache       *cache.Cache
}

type wafEntry struct {
	Token  string
	Expiry time.Time
}

func New() (*Scraper, error) {
	c, err := httpx.NewFirefoxFollowRedirects(fetchTimeout, false)
	if err != nil {
		return nil, err
	}
	s := &Scraper{
		client:          c,
		refreshCh:       make(chan struct{}, 1),
		stopCh:          make(chan struct{}),
		SearchCache:     cache.New(15*time.Minute, 30*time.Minute),
		DetailsCache:    cache.New(30*time.Minute, 60*time.Minute),
		DetailsNegCache: cache.New(5*time.Minute, 10*time.Minute),
		SearchNegCache:  cache.New(5*time.Minute, 10*time.Minute),
		RecsCache:       cache.New(15*time.Minute, 30*time.Minute),
	}
	return s, nil
}

func (s *Scraper) Init(ctx context.Context) error {
	if err := s.warmPool(ctx); err != nil {
		return err
	}
	go s.refreshLoop()
	log.Printf("scraper: initialized with %d WAF tokens", len(s.pool))
	return nil
}

func (s *Scraper) Close() {
	close(s.stopCh)
}

func (s *Scraper) generateToken(ctx context.Context) (string, error) {
	w, err := waf.New(baseURL+"/", "")
	if err != nil {
		return "", err
	}
	return w.GenerateToken(ctx)
}

func (s *Scraper) warmPool(ctx context.Context) error {
	s.poolMu.Lock()
	need := wafPoolSize - len(s.pool)
	s.poolMu.Unlock()
	if need <= 0 {
		return nil
	}

	tokens := make([]string, need)
	errs := make([]error, need)
	var wg sync.WaitGroup
	for i := range need {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokens[i], errs[i] = s.generateToken(ctx)
		}(i)
	}
	wg.Wait()

	s.poolMu.Lock()
	defer s.poolMu.Unlock()
	now := time.Now()
	for i, t := range tokens {
		if errs[i] != nil {
			log.Printf("scraper: warm token %d failed: %v", i, errs[i])
			continue
		}
		if t == "" {
			continue
		}
		s.pool = append(s.pool, wafEntry{Token: t, Expiry: now.Add(wafTTL)})
	}
	return nil
}

func (s *Scraper) peekToken() string {
	now := time.Now()
	i := 0
	for ; i < len(s.pool); i++ {
		if s.pool[i].Expiry.After(now) {
			break
		}
	}
	if i > 0 {
		s.pool = s.pool[i:]
	}
	if len(s.pool) == 0 {
		return ""
	}
	return s.pool[0].Token
}

func (s *Scraper) getToken(ctx context.Context) string {
	s.poolMu.Lock()
	token := s.peekToken()
	s.poolMu.Unlock()
	if token != "" {
		return token
	}
	_ = s.warmPool(ctx)
	s.poolMu.Lock()
	defer s.poolMu.Unlock()
	return s.peekToken()
}

func (s *Scraper) invalidateToken(ctx context.Context, token string) string {
	s.poolMu.Lock()
	filtered := s.pool[:0]
	for _, e := range s.pool {
		if e.Token != token {
			filtered = append(filtered, e)
		}
	}
	s.pool = filtered
	s.poolMu.Unlock()
	_ = s.warmPool(ctx)
	s.poolMu.Lock()
	defer s.poolMu.Unlock()
	return s.peekToken()
}

func (s *Scraper) refreshLoop() {
	interval := time.Duration(float64(wafTTL) * wafRefreshFactor)
	if interval < time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			fresh, err := s.generateToken(ctx)
			cancel()
			if err != nil || fresh == "" {
				log.Printf("scraper: background refresh failed: %v", err)
				continue
			}
			s.poolMu.Lock()
			if len(s.pool) >= wafPoolSize {
				s.pool = s.pool[1:]
			}
			s.pool = append(s.pool, wafEntry{Token: fresh, Expiry: time.Now().Add(wafTTL)})
			s.poolMu.Unlock()
		}
	}
}

func (s *Scraper) TokenSnapshot() (string, int) {
	s.poolMu.Lock()
	defer s.poolMu.Unlock()
	if len(s.pool) == 0 {
		return "", 0
	}
	remaining := int(time.Until(s.pool[0].Expiry).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	return s.pool[0].Token, remaining
}

func (s *Scraper) ForceRefresh(ctx context.Context) (string, error) {
	current, _ := s.TokenSnapshot()
	if current != "" {
		s.invalidateToken(ctx, current)
	} else {
		_ = s.warmPool(ctx)
	}
	token, _ := s.TokenSnapshot()
	if token == "" {
		return "", ErrUpstreamUnavailable
	}
	return token, nil
}

func looksLikeChallenge(body string) bool {
	head := body
	if len(head) > 600 {
		head = head[:600]
	}
	return strings.Contains(head, challengeMarker1) || strings.Contains(head, challengeMarker2)
}

func (s *Scraper) rnetGet(ctx context.Context, target, token string) (string, error) {
	req, err := fhttp.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("user-agent", imdbUserAgent)
	req.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	req.Header.Set("accept-encoding", "gzip, deflate")
	req.Header.Set("referer", baseURL)
	if token != "" {
		req.Header.Set("cookie", "aws-waf-token="+token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	body, err := httpx.ReadAll(resp)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 500 {
		log.Printf("scraper: upstream %d for %s", resp.StatusCode, target)
		return "", nil
	}
	return string(body), nil
}

func (s *Scraper) FetchHTML(ctx context.Context, target string) (string, error) {
	token := s.getToken(ctx)
	anySuccess := false
	for attempts := 0; attempts < 2; attempts++ {
		body, err := s.rnetGet(ctx, target, token)
		if err != nil {
			continue
		}
		anySuccess = true
		if body == "" {
			return "", nil
		}
		if !looksLikeChallenge(body) {
			return body, nil
		}
		log.Printf("scraper: WAF challenge on %s, rotating token", target)
		if token != "" {
			token = s.invalidateToken(ctx, token)
		} else {
			token = s.getToken(ctx)
		}
		if token == "" {
			break
		}
	}
	if !anySuccess {
		return "", &UpstreamUnavailableError{URL: target}
	}
	return "", &WAFBlockedError{URL: target}
}

func (s *Scraper) FetchJSON(ctx context.Context, target string) (string, error) {
	req, err := fhttp.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("user-agent", imdbUserAgent)
	req.Header.Set("accept", "application/json")
	req.Header.Set("accept-encoding", "gzip, deflate")
	req.Header.Set("referer", baseURL+"/")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", &UpstreamUnavailableError{URL: target}
	}
	body, err := httpx.ReadAll(resp)
	if err != nil {
		return "", &UpstreamUnavailableError{URL: target}
	}
	if resp.StatusCode != 200 {
		return "", nil
	}
	return string(body), nil
}
