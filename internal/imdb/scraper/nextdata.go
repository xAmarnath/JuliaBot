package scraper

import (
	"regexp"
	"strings"

	json "github.com/goccy/go-json"
)

var nextDataRe = regexp.MustCompile(`(?s)<script id="__NEXT_DATA__" type="application/json">(.*?)</script>`)

func extractNextData(html string) map[string]any {
	m := nextDataRe.FindStringSubmatch(html)
	if len(m) < 2 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(m[1]), &out); err != nil {
		return nil
	}
	return out
}

func reducePosterQuality(url string) string {
	if url == "" {
		return ""
	}
	if !strings.Contains(url, "_V1_") {
		return url
	}
	url = strings.ReplaceAll(url, "UX1000", "UX500")
	url = strings.ReplaceAll(url, "UX1500", "UX500")
	return url
}

func walk(m any, path ...string) any {
	cur := m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		v, ok := mm[p]
		if !ok || v == nil {
			return nil
		}
		cur = v
	}
	return cur
}

func walkString(m any, path ...string) string {
	v := walk(m, path...)
	s, _ := v.(string)
	return s
}

func walkInt(m any, path ...string) *int {
	v := walk(m, path...)
	switch t := v.(type) {
	case float64:
		n := int(t)
		return &n
	case int:
		return &t
	}
	return nil
}

func walkInt64(m any, path ...string) *int64 {
	v := walk(m, path...)
	switch t := v.(type) {
	case float64:
		n := int64(t)
		return &n
	case int64:
		return &t
	case int:
		n := int64(t)
		return &n
	}
	return nil
}

func walkFloat(m any, path ...string) *float64 {
	v := walk(m, path...)
	f, ok := v.(float64)
	if !ok {
		return nil
	}
	return &f
}

func walkBool(m any, path ...string) bool {
	v := walk(m, path...)
	b, _ := v.(bool)
	return b
}

func walkList(m any, path ...string) []any {
	v := walk(m, path...)
	l, _ := v.([]any)
	return l
}

func walkMap(m any, path ...string) map[string]any {
	v := walk(m, path...)
	mp, _ := v.(map[string]any)
	return mp
}
