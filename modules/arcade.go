package modules

import (
	"embed"
	"strings"

	tg "github.com/xAmarnath/gogram/telegram"
)

//go:embed arcade_ttt.html arcade_blocks.html arcade_2048.html
var arcadeCards embed.FS

//go:embed arcade_engine.js
var arcadeEngine string

func arcadeCard(game string) string {
	if game != "blocks" && game != "2048" {
		game = "ttt"
	}
	card, _ := arcadeCards.ReadFile("arcade_" + game + ".html")
	return strings.Replace(string(card), "/* ARCADE_ENGINE */", arcadeEngine, 1)
}

func sendArcade(m *tg.NewMessage, game string) error {
	_, err := m.ReplyMedia(&tg.InputMediaWidget{Width: 340, Height: 0, Html: arcadeCard(game)},
		&tg.MediaOptions{Caption: "Julia Arcade · /tictactoe · /blocks · /2048. Each player has their own game."})
	if err == nil {
		return nil
	}
	m.Client.Log.Error("[arcade] %s card rejected: %v", game, err)
	// Explicit RPC rejections have not delivered a card. Give the user a
	// useful reply; transport timeouts may have delivered it already.
	if widgetUnavailable(err) || tg.MatchError(err, "INPUT_MEDIA_WIDGET_TOO_LARGE") {
		_, replyErr := m.Reply("Telegram couldn't open this game here. Try the command in @XyumiBot's private chat. If it still fails, please try again shortly.")
		return replyErr
	}
	return err
}

func init() {
	QueueHandlerRegistration(func() {
		for command, game := range map[string]string{"arcade": "ttt", "tictactoe": "ttt", "blocks": "blocks", "2048": "2048"} {
			OnCommand(Client, "cmd:"+command, func(m *tg.NewMessage) error {
				return sendArcade(m, game)
			})
		}
	})
	Mods.AddModule("Arcade", "<b>Julia Arcade</b>\n/arcade or /tictactoe — play the machine\n/blocks — falling blocks with touch controls\n/2048 — swipe to merge 2 → 4 → 8 → 2048\nGames run in Telegram widgets, with separate boards for each player.")
}
