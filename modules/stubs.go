package modules

import (
	"strings"

	tg "github.com/xAmarnath/gogram/telegram"
)

func ExtractText(m *tg.NewMessage) string {
	args := strings.TrimSpace(m.Args())
	if args != "" {
		return args
	}
	if m.IsReply() {
		reply, err := m.GetReplyMessage()
		if err == nil && reply != nil {
			return reply.Text()
		}
	}
	return ""
}
