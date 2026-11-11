package modules

import (
	"bytes"
	"compress/zlib"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArcadeTelegramPayloadLimits(t *testing.T) {
	for _, game := range []string{"ttt", "blocks", "2048"} {
		t.Run(game, func(t *testing.T) {
			html := arcadeCard(game)
			if len(html) == 0 || len(html) > 32768 || strings.Contains(html, "ARCADE_") {
				t.Fatal("invalid or incomplete card", len(html))
			}
			for _, level := range []int{zlib.DefaultCompression, zlib.BestCompression} {
				var compressed bytes.Buffer
				z, _ := zlib.NewWriterLevel(&compressed, level)
				_, _ = z.Write([]byte(html))
				_ = z.Close()
				if compressed.Len() > 4096 {
					t.Fatalf("Telegram rejects card: %d compressed bytes (limit 4096)", compressed.Len())
				}
				t.Logf("%d raw / %d compressed bytes (level %d)", len(html), compressed.Len(), level)
			}
			if dir := os.Getenv("ARCADE_TEST_ARTIFACTS"); dir != "" {
				if err := os.WriteFile(filepath.Join(dir, "arcade-"+game+".html"), []byte(html), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
