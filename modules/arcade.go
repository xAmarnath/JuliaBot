package modules

import (
	"embed"
	"strings"

	tg "github.com/xAmarnath/gogram/telegram"
)

//go:embed arcade_ttt.html arcade_blocks.html arcade_2048.html arcade_*_engine.js arcade.css
var arcadeCards embed.FS

func arcadeCard(game string) string {
	if game != "blocks" && game != "2048" {
		game = "ttt"
	}
	card, _ := arcadeCards.ReadFile("arcade_" + game + ".html")
	engine, _ := arcadeCards.ReadFile("arcade_" + game + "_engine.js")
	style, _ := arcadeCards.ReadFile("arcade.css")
	return strings.NewReplacer("/* ARCADE_ENGINE */", string(engine), "/* ARCADE_STYLE */", string(style)).Replace(string(card))
}

func sendArcade(m *tg.NewMessage, game string) error {
	_, err := m.ReplyMedia(&tg.InputMediaWidget{Width: 340, Height: 0, Html: arcadeCard(game)})
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
	Mods.AddModule("Arcade", "<b>Games</b>\n/arcade or /tictactoe — play the machine\n/blocks — Tetris with touch controls\n/2048 — swipe to merge on 4×4, 5×5 or 6×6 grids\nGames run in Telegram widgets, with separate boards for each player.")
}
