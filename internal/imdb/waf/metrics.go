package waf

import (
	"math/rand/v2"

	json "github.com/goccy/go-json"
)

type metric struct {
	Name  string      `json:"name"`
	Value json.Number `json:"value"`
	Unit  string      `json:"unit"`
}

func buildMetrics() []metric {
	return []metric{
		{Name: "2", Value: numFloat(rand.Float64()), Unit: "2"},
		{Name: "100", Value: "0", Unit: "2"},
		{Name: "101", Value: "0", Unit: "2"},
		{Name: "102", Value: "0", Unit: "2"},
		{Name: "103", Value: "8", Unit: "2"},
		{Name: "104", Value: "0", Unit: "2"},
		{Name: "105", Value: "0", Unit: "2"},
		{Name: "106", Value: "0", Unit: "2"},
		{Name: "107", Value: "0", Unit: "2"},
		{Name: "108", Value: "1", Unit: "2"},
		{Name: "undefined", Value: "0", Unit: "2"},
		{Name: "110", Value: "0", Unit: "2"},
		{Name: "111", Value: "2", Unit: "2"},
		{Name: "112", Value: "0", Unit: "2"},
		{Name: "undefined", Value: "0", Unit: "2"},
		{Name: "3", Value: "4", Unit: "2"},
		{Name: "7", Value: "0", Unit: "4"},
		{Name: "1", Value: numFloat(5 + rand.Float64()*15), Unit: "2"},
		{Name: "4", Value: "36.5", Unit: "2"},
		{Name: "5", Value: numFloat(rand.Float64()), Unit: "2"},
		{Name: "6", Value: numFloat(100 + rand.Float64()*400), Unit: "2"},
		{Name: "0", Value: numFloat(135 + rand.Float64()*(500-135)), Unit: "2"},
		{Name: "8", Value: "1", Unit: "4"},
	}
}

func numFloat(f float64) json.Number {
	b, _ := json.Marshal(f)
	return json.Number(b)
}
