package db

import (
	"reflect"
	"testing"
)

func TestGreetingIDsPreserveLegacyCleanup(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []int32
	}{
		{"", nil}, {"0", nil}, {"123", []int32{123}},
		{"[123,124]", []int32{123, 124}},
	} {
		got, err := decodeGreetingIDs([]byte(tc.raw))
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("decode %q = %v, %v; want %v", tc.raw, got, err, tc.want)
		}
	}
	if _, err := decodeGreetingIDs([]byte("invalid")); err == nil {
		t.Fatal("corrupt cleanup state accepted")
	}
}
