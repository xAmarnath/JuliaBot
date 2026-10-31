package waf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	json "github.com/goccy/go-json"

	"main/internal/imdb/httpx"
)

const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"

var (
	fetchHeaders = map[string]string{
		"user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
		"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"accept-language": "en-US,en;q=0.5",
		"accept-encoding": "gzip, deflate",
	}

	apiHeaders = map[string]string{
		"connection":                "keep-alive",
		"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"accept-encoding":           "gzip, deflate",
		"accept-language":           "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6",
		"cache-control":             "no-cache",
		"pragma":                    "no-cache",
		"priority":                  "u=0, i",
		"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
		"sec-ch-ua-mobile":          "?0",
		"sec-ch-ua-platform":        `"Windows"`,
		"sec-fetch-dest":            "document",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-site":            "same-origin",
		"upgrade-insecure-requests": "1",
	}
)

var (
	ErrChallengeMissing = errors.New("challenge script not found on page")
	ErrTokenMissing     = errors.New("verify response contained no token")
)

type Waf struct {
	url       string
	userAgent string
	domain    string
	client    httpx.Client
}

func New(pageURL, userAgent string) (*Waf, error) {
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	c, err := httpx.NewFirefox(45*time.Second, true)
	if err != nil {
		return nil, err
	}
	return &Waf{
		url:       pageURL,
		userAgent: userAgent,
		domain:    extractDomain(pageURL),
		client:    c,
	}, nil
}

func extractDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	host := raw
	if err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	if !strings.HasPrefix(host, "www.") {
		host = "www." + host
	}
	return host
}

func (w *Waf) newRequest(ctx context.Context, method, target string, body io.Reader, headers map[string]string, contentType string) (*fhttp.Request, error) {
	req, err := fhttp.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if w.userAgent != "" {
		req.Header.Set("user-agent", w.userAgent)
	}
	if contentType != "" {
		req.Header.Set("content-type", contentType)
	}
	return req, nil
}

func (w *Waf) fetchChallenge(ctx context.Context) (string, error) {
	req, err := w.newRequest(ctx, "GET", w.url, nil, fetchHeaders, "")
	if err != nil {
		return "", err
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return "", err
	}
	body, err := httpx.ReadAll(resp)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func extractChallenge(html string) (gokuProps json.RawMessage, host string, err error) {
	const (
		gokuMarker      = "window.gokuProps = "
		challengeMarker = `src="https://`
		challengeSuffix = "/challenge.js"
	)
	gi := strings.Index(html, gokuMarker)
	if gi < 0 {
		return nil, "", ErrChallengeMissing
	}
	after := html[gi+len(gokuMarker):]
	semi := strings.Index(after, ";")
	if semi < 0 {
		return nil, "", ErrChallengeMissing
	}
	propsRaw := after[:semi]
	if !json.Valid([]byte(propsRaw)) {
		return nil, "", fmt.Errorf("gokuProps not valid JSON: %s", truncate(propsRaw, 200))
	}
	gokuProps = json.RawMessage(propsRaw)

	si := strings.Index(html, challengeMarker)
	if si < 0 {
		return nil, "", ErrChallengeMissing
	}
	afterSrc := html[si+len(challengeMarker):]
	ei := strings.Index(afterSrc, challengeSuffix)
	if ei < 0 {
		return nil, "", ErrChallengeMissing
	}
	host = afterSrc[:ei]
	return gokuProps, host, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

type inputsResponse struct {
	ChallengeType string          `json:"challenge_type"`
	Challenge     json.RawMessage `json:"challenge"`
	Difficulty    int             `json:"difficulty"`
}

func (w *Waf) getChallengeInputs(ctx context.Context, hostURL string) (*inputsResponse, error) {
	target := "https://" + hostURL + "/inputs?client=browser"
	req, err := w.newRequest(ctx, "GET", target, nil, apiHeaders, "")
	if err != nil {
		return nil, err
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := httpx.ReadAll(resp)
	if err != nil {
		return nil, err
	}
	var inp inputsResponse
	if err := json.Unmarshal(body, &inp); err != nil {
		return nil, fmt.Errorf("decode inputs: %w (body: %s)", err, truncate(string(body), 200))
	}
	return &inp, nil
}

type signalValue struct {
	Present string `json:"Present"`
}

type signal struct {
	Name  string      `json:"name"`
	Value signalValue `json:"value"`
}

type powBody struct {
	Challenge     json.RawMessage `json:"challenge"`
	Solution      string          `json:"solution"`
	Signals       []signal        `json:"signals"`
	Checksum      string          `json:"checksum"`
	ExistingToken any             `json:"existing_token"`
	Client        string          `json:"client"`
	Domain        string          `json:"domain"`
	Metrics       []metric        `json:"metrics"`
	GokuProps     json.RawMessage `json:"goku_props"`
}

type bandwidthMetadata struct {
	Challenge json.RawMessage `json:"challenge"`
	Solution  any             `json:"solution"`
	Signals   []signal        `json:"signals"`
	Checksum  string          `json:"checksum"`
	Client    string          `json:"client"`
	Domain    string          `json:"domain"`
	Metrics   []metric        `json:"metrics"`
	GokuProps json.RawMessage `json:"goku_props"`
}

type solutionKind int

const (
	kindPOW solutionKind = iota
	kindBandwidth
)

type solution struct {
	Kind         solutionKind
	POWBody      *powBody
	SolutionData string
	Metadata     *bandwidthMetadata
}

func (w *Waf) buildSolution(inputs *inputsResponse, gokuProps json.RawMessage) (*solution, error) {
	payload, err := buildPayload(w.userAgent)
	if err != nil {
		return nil, err
	}
	metrics := buildMetrics()
	signals := []signal{{Name: "Zoey", Value: signalValue{Present: payload.Encrypted}}}

	if inputs.ChallengeType == bandwidthChallenge {
		return &solution{
			Kind:         kindBandwidth,
			SolutionData: computeBandwidth(inputs.Difficulty),
			Metadata: &bandwidthMetadata{
				Challenge: inputs.Challenge,
				Solution:  nil,
				Signals:   signals,
				Checksum:  payload.Checksum,
				Client:    "Browser",
				Domain:    w.domain,
				Metrics:   metrics,
				GokuProps: gokuProps,
			},
		}, nil
	}

	challengeInput, err := unwrapChallengeInput(inputs.Challenge)
	if err != nil {
		return nil, err
	}
	var solvedNonce string
	if inputs.ChallengeType == scryptChallenge {
		solvedNonce, err = computeScrypt(challengeInput, payload.Checksum, inputs.Difficulty)
		if err != nil {
			return nil, err
		}
	} else {
		solvedNonce = computeSHA256PoW(challengeInput, payload.Checksum, inputs.Difficulty)
	}
	return &solution{
		Kind: kindPOW,
		POWBody: &powBody{
			Challenge:     inputs.Challenge,
			Solution:      solvedNonce,
			Signals:       signals,
			Checksum:      payload.Checksum,
			ExistingToken: nil,
			Client:        "Browser",
			Domain:        w.domain,
			Metrics:       metrics,
			GokuProps:     gokuProps,
		},
	}, nil
}

const scryptChallenge = "h72f957df656e80ba55f5d8ce2e8c7ccb59687dba3bfb273d54b08a261b2f3002"

func unwrapChallengeInput(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("empty challenge")
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", err
		}
		return s, nil
	}
	var obj struct {
		Input string `json:"input"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", err
	}
	if obj.Input == "" {
		return "", errors.New("challenge object missing input")
	}
	return obj.Input, nil
}

type verifyResponse struct {
	Token string `json:"token"`
}

func (w *Waf) postSolution(ctx context.Context, hostURL string, sol *solution) (string, error) {
	switch sol.Kind {
	case kindPOW:
		body, err := json.Marshal(sol.POWBody)
		if err != nil {
			return "", err
		}
		target := "https://" + hostURL + "/verify"
		req, err := w.newRequest(ctx, "POST", target, bytes.NewReader(body), apiHeaders, "text/plain;charset=UTF-8")
		if err != nil {
			return "", err
		}
		resp, err := w.client.Do(req)
		if err != nil {
			return "", err
		}
		raw, err := httpx.ReadAll(resp)
		if err != nil {
			return "", err
		}
		var v verifyResponse
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", fmt.Errorf("decode verify: %w (body: %s)", err, truncate(string(raw), 200))
		}
		if v.Token == "" {
			return "", ErrTokenMissing
		}
		return v.Token, nil

	case kindBandwidth:
		body, contentType, err := buildMultipart(sol.SolutionData, sol.Metadata)
		if err != nil {
			return "", err
		}
		target := "https://" + hostURL + "/mp_verify"
		req, err := w.newRequest(ctx, "POST", target, bytes.NewReader(body), apiHeaders, contentType)
		if err != nil {
			return "", err
		}
		resp, err := w.client.Do(req)
		if err != nil {
			return "", err
		}
		raw, err := httpx.ReadAll(resp)
		if err != nil {
			return "", err
		}
		var v verifyResponse
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", fmt.Errorf("decode mp_verify: %w (body: %s)", err, truncate(string(raw), 200))
		}
		if v.Token == "" {
			return "", ErrTokenMissing
		}
		return v.Token, nil
	}
	return "", errors.New("unknown solution kind")
}

func buildMultipart(solutionData string, meta *bandwidthMetadata) ([]byte, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	dataPart, err := mw.CreateFormField("solution_data")
	if err != nil {
		return nil, "", err
	}
	if _, err := dataPart.Write([]byte(solutionData)); err != nil {
		return nil, "", err
	}

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, "", err
	}
	metaPart, err := mw.CreateFormField("solution_metadata")
	if err != nil {
		return nil, "", err
	}
	if _, err := metaPart.Write(metaBytes); err != nil {
		return nil, "", err
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), mw.FormDataContentType(), nil
}

func (w *Waf) GenerateToken(ctx context.Context) (string, error) {
	html, err := w.fetchChallenge(ctx)
	if err != nil {
		return "", fmt.Errorf("fetch challenge: %w", err)
	}
	goku, host, err := extractChallenge(html)
	if err != nil {
		return "", fmt.Errorf("extract challenge: %w", err)
	}
	inputs, err := w.getChallengeInputs(ctx, host)
	if err != nil {
		return "", fmt.Errorf("challenge inputs: %w", err)
	}
	sol, err := w.buildSolution(inputs, goku)
	if err != nil {
		return "", fmt.Errorf("build solution: %w", err)
	}
	token, err := w.postSolution(ctx, host, sol)
	if err != nil {
		return "", fmt.Errorf("post solution: %w", err)
	}
	return token, nil
}
