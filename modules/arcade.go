package modules

import (
	_ "embed"
	"strings"

	tg "github.com/xAmarnath/gogram/telegram"
)

//go:embed arcade.html
var arcadeHTML string

//go:embed arcade_engine.js
var arcadeEngine string

func arcadeCard(game string) string {
	if game != "blocks" && game != "2048" {
		game = "ttt"
	}
	card := strings.Replace(arcadeHTML, "/* ARCADE_ENGINE */", arcadeEngine, 1)
	return strings.Replace(card, "INITIAL_GAME", game, 1)
}

func init() {
	QueueHandlerRegistration(func() {
		for command, game := range map[string]string{"arcade": "ttt", "tictactoe": "ttt", "blocks": "blocks", "2048": "2048"} {
			OnCommand(Client, "cmd:"+command, func(m *tg.NewMessage) error {
				_, err := m.ReplyMedia(&tg.InputMediaWidget{Width: 340, Height: 0, Html: arcadeCard(game)},
					&tg.MediaOptions{Caption: "Julia Arcade · Tic-tac-toe vs machine, falling blocks & swipe 2048. Each player has their own game. Update Telegram if the card is unavailable."})
				return err
			})
		}
	})
	Mods.AddModule("Arcade", "<b>Julia Arcade</b>\n/arcade or /tictactoe — play the machine\n/blocks — falling blocks with touch controls\n/2048 — swipe to merge 2 → 4 → 8 → 2048\nGames run in Telegram widgets, with separate boards for each player.")
}
