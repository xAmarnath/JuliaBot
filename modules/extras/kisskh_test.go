package extras

import (
	"main/internal/kisskh"
	"testing"
)

func TestKissPickerFourPerRow(t *testing.T) {
	d := &kisskh.Drama{}
	for i := 1; i <= 30; i++ {
		d.Episodes = append(d.Episodes, kisskh.Episode{ID: int64(227000 + i), Number: float64(i)})
	}
	kb := kissKeyboard("1234567890abcdef", d, 0)
	if len(kb.Rows) != 8 {
		t.Fatal("expected six episode rows, navigation and close", len(kb.Rows))
	}
	for i := 0; i < 6; i++ {
		if len(kb.Rows[i].Buttons) != 4 {
			t.Fatal("not four episodes per row")
		}
	}
	last := kissKeyboard("1234567890abcdef", d, 1)
	if len(last.Rows[0].Buttons) != 4 || len(last.Rows[1].Buttons) != 2 {
		t.Fatal("last page layout")
	}
}
