package scraper

import "errors"

var (
	ErrWAFBlocked          = errors.New("WAF blocked after retries")
	ErrUpstreamUnavailable = errors.New("upstream network failure")
	ErrParse               = errors.New("failed to parse upstream response")
)

type WAFBlockedError struct{ URL string }

func (e *WAFBlockedError) Error() string { return "WAF blocked after retries: " + e.URL }
func (*WAFBlockedError) Is(target error) bool {
	return target == ErrWAFBlocked
}

type UpstreamUnavailableError struct{ URL string }

func (e *UpstreamUnavailableError) Error() string { return "upstream network failure: " + e.URL }
func (*UpstreamUnavailableError) Is(target error) bool {
	return target == ErrUpstreamUnavailable
}

type ParseError struct{ Detail string }

func (e *ParseError) Error() string { return e.Detail }
func (*ParseError) Is(target error) bool {
	return target == ErrParse
}
