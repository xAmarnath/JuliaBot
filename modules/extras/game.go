package extras

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"math"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
	"main/internal/mongostore"
	modules "main/modules"
	"main/modules/db"
)

const gamePlayersBucket = "game_players"

type Fighter struct {
	ID     int64  `json:"id"`
	Char   string `json:"char"`
	Rarity int    `json:"rarity"`
	Level  int    `json:"level"`
	XP     int64  `json:"xp"`
	Wins   int    `json:"wins"`
	Losses int    `json:"losses"`
}

type Player struct {
	ID            int64            `json:"id"`
	Name          string           `json:"name"`
	Wallet        int64            `json:"wallet"`
	Bank          int64            `json:"bank"`
	Gems          int64            `json:"gems"`
	XP            int64            `json:"xp"`
	Level         int              `json:"level"`
	DailyStreak   int              `json:"daily_streak"`
	LastDaily     int64            `json:"last_daily"`
	Fighters      []*Fighter       `json:"fighters"`
	ActiveFighter int64            `json:"active_fighter"`
	Stats         map[string]int64 `json:"stats"`
	Chats         []int64          `json:"chats"`
	NextID        int64            `json:"next_id"`
	Created       int64            `json:"created"`
	legacy        map[string]json.RawMessage
}

// Retain retired inventories and other saved fields when updating a player.
// This also lets older backups be imported without discarding their progress.
func (p *Player) UnmarshalJSON(data []byte) error {
	type plain Player
	if err := json.Unmarshal(data, (*plain)(p)); err != nil {
		return err
	}
	return json.Unmarshal(data, &p.legacy)
}

func (p Player) MarshalJSON() ([]byte, error) {
	type plain Player
	data, err := json.Marshal(plain(p))
	if err != nil {
		return nil, err
	}
	fields := make(map[string]json.RawMessage, len(p.legacy))
	for k, v := range p.legacy {
		fields[k] = v
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

func (p *Player) prepare() {
	p.Name = gameName(p.Name)
	p.Level = max(1, p.Level)
	if p.Stats == nil {
		p.Stats = make(map[string]int64)
	}
	// Return each player's escrow from an unfinished retired turn-based duel.
	if raw := p.legacy["duel"]; len(raw) > 0 {
		var duel struct {
			Players [2]int64
			Wager   int64
			Done    bool
		}
		if json.Unmarshal(raw, &duel) == nil && !duel.Done && duel.Wager > 0 && (duel.Players[0] == p.ID || duel.Players[1] == p.ID) {
			p.Wallet += duel.Wager
		}
		delete(p.legacy, "duel")
	}
	for _, f := range p.Fighters {
		if f != nil {
			p.NextID = max(p.NextID, f.ID)
			f.Level = max(1, f.Level)
		}
	}
	if p.active() == nil {
		p.NextID++
		p.Fighters = append(p.Fighters, &Fighter{ID: p.NextID, Char: "Rookie", Level: 1})
		p.ActiveFighter = p.NextID
	}
}

func (p *Player) active() *Fighter {
	var best *Fighter
	for _, f := range p.Fighters {
		if f == nil {
			continue
		}
		if f.ID == p.ActiveFighter {
			return f
		}
		if best == nil || f.power() > best.power() {
			best = f
		}
	}
	return best
}

func (f *Fighter) power() int {
	return 50 + min(max(f.Level, 1), 1000)*10 + min(max(f.Rarity, 0), 5)*25
}
func (p *Player) coins() int64 { return p.Wallet + p.Bank }
func (p *Player) spend(n int64) bool {
	if n <= 0 || p.coins() < n {
		return false
	}
	fromWallet := min(max(p.Wallet, 0), n)
	p.Wallet -= fromWallet
	p.Bank -= n - fromWallet
	return true
}
func (p *Player) addXP(n int64) {
	p.XP += n
	for p.Level < 10000 {
		next := int64(60 * math.Pow(float64(p.Level), 1.6))
		if p.XP < next {
			break
		}
		p.XP -= next
		p.Level++
	}
}

func gameDaily(p *Player, now int64) (string, error) {
	if p.LastDaily != 0 && now < p.LastDaily+86400 {
		return "", fmt.Errorf("Your daily reward is ready in %s.", (time.Duration(p.LastDaily+86400-now) * time.Second).Round(time.Minute))
	}
	if now-p.LastDaily > 2*86400 {
		p.DailyStreak = 0
	}
	p.DailyStreak++
	p.LastDaily = now
	reward := int64(500 + 100*min(p.DailyStreak, 30) + 20*p.Level)
	p.Wallet += reward
	p.addXP(50)
	return fmt.Sprintf("🎁 +%d coins and 50 XP!\n🔥 Daily streak: %d\n🪙 Balance: %d", reward, p.DailyStreak, p.coins()), nil
}

var gameShop = []struct {
	key, name string
	price     int64
	rarity    int
}{
	{"scout", "Scout", 800, 1}, {"knight", "Knight", 2500, 2}, {"dragon", "Dragon", 8000, 3},
}

func gameBuy(p *Player, item string) (string, error) {
	if item == "upgrade" {
		f := p.active()
		if f.Level >= 100 {
			return "", errors.New("Your fighter is already at the shop's level cap (100).")
		}
		cost := int64(f.Level) * 250
		if !p.spend(cost) {
			return "", fmt.Errorf("You need %d coins for this upgrade.", cost)
		}
		f.Level++
		return fmt.Sprintf("⬆️ %s is now level %d!", html.EscapeString(gameName(f.Char)), f.Level), nil
	}
	for _, it := range gameShop {
		if it.key != item {
			continue
		}
		for _, f := range p.Fighters {
			if f != nil && f.Char == it.name {
				return "", errors.New("You already own that fighter. Use /equip or /upgrade.")
			}
		}
		if !p.spend(it.price) {
			return "", fmt.Errorf("You need %d coins for %s.", it.price, it.name)
		}
		p.NextID++
		p.Fighters = append(p.Fighters, &Fighter{ID: p.NextID, Char: it.name, Rarity: it.rarity, Level: 1})
		p.ActiveFighter = p.NextID
		return "✅ " + it.name + " joined your team and is ready to battle!", nil
	}
	return "", errors.New("Use /buy scout, /buy knight, /buy dragon or /buy upgrade.")
}

func battleReady(p *Player, now int64) error {
	if next := p.Stats["last_battle"] + 90; now < next {
		return fmt.Errorf("%s can battle again in %ds.", p.Name, next-now)
	}
	return nil
}

// Three quick rounds. No wagers, energy, spells or turn state to get stuck in.
func gameBattle(a, b *Player, now int64, roll func(int) int) (string, error) {
	if err := battleReady(a, now); err != nil {
		return "", err
	}
	if b != nil {
		if a.ID == b.ID {
			return "", errors.New("Choose another player.")
		}
		if err := battleReady(b, now); err != nil {
			return "", err
		}
	}
	foeName, foePower := "Arena rival", 70+a.Level*10
	if b != nil {
		foeName, foePower = b.Name, b.active().power()
	}
	wins := 0
	for range 3 {
		if a.active().power()*(50+roll(101)) >= foePower*(50+roll(101)) {
			wins++
		}
	}
	a.Stats["last_battle"] = now
	a.addXP(20)
	winner := a
	if wins < 2 {
		winner = b
	}
	if b != nil {
		b.Stats["last_battle"] = now
		b.addXP(20)
	}
	for _, p := range []*Player{a, b} {
		if p == nil {
			continue
		}
		if p == winner {
			p.Wallet += 150
			p.Stats["wins"]++
			p.active().Wins++
		} else {
			p.Wallet += 25
			p.Stats["losses"]++
			p.active().Losses++
		}
	}
	name := foeName
	if winner != nil {
		name = winner.Name
	}
	return fmt.Sprintf("⚔️ %s vs %s\nRounds: %d–%d\n🏆 %s wins!\nWinner: 150 coins · Runner-up: 25 coins · +20 XP each", html.EscapeString(a.Name), html.EscapeString(foeName), wins, 3-wins, html.EscapeString(name)), nil
}

type gameChallenge struct {
	ID       uint64
	From, To int64
	Name     string
	Expires  int64
}
type gameStore struct {
	mu         sync.Mutex
	flushMu    sync.Mutex
	players    map[int64]*Player
	dirty      map[int64]uint64
	revision   uint64
	challenges map[int64]gameChallenge
	loaded     bool
}

var game = &gameStore{players: map[int64]*Player{}, dirty: map[int64]uint64{}, challenges: map[int64]gameChallenge{}}

func (s *gameStore) mark(id int64) { s.revision++; s.dirty[id] = s.revision }

func StartGame(ctx context.Context) error {
	database, err := db.GetDB()
	if err != nil {
		return err
	}
	s := game
	s.mu.Lock()
	err = database.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte(gamePlayersBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			if v == nil {
				return nil
			}
			var p Player
			if err := json.Unmarshal(v, &p); err != nil {
				return fmt.Errorf("load game player %s: %w", k, err)
			}
			if p.ID <= 0 {
				return errors.New("invalid saved game player ID")
			}
			p.prepare()
			s.players[p.ID] = &p
			s.mark(p.ID)
			return nil
		})
	})
	s.loaded = err == nil
	s.mu.Unlock()
	if err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				FlushGame()
			}
		}
	}()
	// Replace the old Mini App menu with Telegram's normal command menu.
	go func() {
		if _, err := modules.Client.BotsSetBotMenuButton(&tg.InputUserEmpty{}, &tg.BotMenuButtonCommands{}); err != nil {
			log.Printf("reset game menu: %v", err)
		}
	}()
	return nil
}

func gameName(name string) string {
	r := []rune(name)
	if len(r) > 48 {
		return string(r[:48]) + "?"
	}
	return name
}

func (s *gameStore) player(id int64, name string, chat int64) *Player {
	p := s.players[id]
	if p == nil {
		p = &Player{ID: id, Name: name, Wallet: 1000, Level: 1, Created: time.Now().Unix()}
		p.prepare()
		s.players[id] = p
	}
	if name != "" {
		p.Name = gameName(name)
	}
	if chat != 0 {
		found := false
		for _, c := range p.Chats {
			if c == chat {
				found = true
				break
			}
		}
		if !found {
			p.Chats = append(p.Chats, chat)
		}
	}
	s.mark(id)
	return p
}

// Snapshot under the lock, then save outside it so Mongo latency cannot block play.
func (s *gameStore) flush(save func(map[int64][]byte) error) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.Lock()
	data := map[int64][]byte{}
	versions := map[int64]uint64{}
	for id, version := range s.dirty {
		raw, err := json.Marshal(s.players[id])
		if err != nil {
			s.mu.Unlock()
			return err
		}
		data[id], versions[id] = raw, version
	}
	s.mu.Unlock()
	if len(data) == 0 {
		return nil
	}
	if err := save(data); err != nil {
		return err
	}
	s.mu.Lock()
	for id, v := range versions {
		if s.dirty[id] == v {
			delete(s.dirty, id)
		}
	}
	s.mu.Unlock()
	return nil
}

func FlushGame() {
	err := game.flush(func(data map[int64][]byte) error {
		database, err := db.GetDB()
		if err != nil {
			return err
		}
		return database.Update(func(tx *mongostore.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte(gamePlayersBucket))
			if err != nil {
				return err
			}
			for id, raw := range data {
				if err := b.Put([]byte(strconv.FormatInt(id, 10)), raw); err != nil {
					return err
				}
			}
			return nil
		})
	})
	if err != nil {
		log.Printf("save game: %v", err)
	}
}

func gameMenu(id int64) *tg.ReplyInlineMarkup {
	button := func(label, action string) tg.KeyboardInlineButton {
		return tg.Button.Data(label, fmt.Sprintf("jg:%d:%s", id, action))
	}
	return tg.NewKeyboard().AddRow(button("🎁 Daily", "daily"), button("⚔️ Battle", "battle")).AddRow(button("🛒 Shop", "shop"), button("🏆 Leaders", "lb")).Build()
}

func (s *gameStore) action(id int64, name string, chat int64, action, args string, now int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return "", errors.New("The game is still starting. Try again shortly.")
	}
	p := s.player(id, name, chat)
	switch action {
	case "daily":
		return gameDaily(p, now)
	case "battle", "spar":
		return gameBattle(p, nil, now, rand.IntN)
	case "buy":
		return gameBuy(p, strings.ToLower(strings.TrimSpace(args)))
	case "upgrade":
		return gameBuy(p, "upgrade")
	case "shop":
		return fmt.Sprintf("🛒 <b>Fighter shop</b> · %d coins\n\n/buy scout — 800 coins\n/buy knight — 2,500 coins\n/buy dragon — 8,000 coins\n/upgrade — %d coins to level up your active fighter\n\n/fighters · /equip &lt;id&gt;", p.coins(), int64(p.active().Level)*250), nil
	case "equip":
		fid, _ := strconv.ParseInt(strings.TrimSpace(args), 10, 64)
		for _, f := range p.Fighters {
			if f != nil && f.ID == fid {
				p.ActiveFighter = fid
				return "⭐ Ready: " + html.EscapeString(gameName(f.Char)), nil
			}
		}
		return "", errors.New("Use /fighters to find an ID, then /equip <id>.")
	case "fighters":
		var out strings.Builder
		out.WriteString("⚔️ <b>Your fighters</b>\n")
		for _, f := range p.Fighters {
			if f != nil && out.Len() < 3000 {
				fmt.Fprintf(&out, "#%d %s · Lv%d · power %d\n", f.ID, html.EscapeString(gameName(f.Char)), f.Level, f.power())
			}
		}
		out.WriteString("\n/equip &lt;id&gt; · /upgrade")
		return out.String(), nil
	case "lb", "leaderboard":
		metric := firstField(args)
		if metric != "wins" && metric != "level" {
			metric = "coins"
		}
		type row struct {
			id    int64
			name  string
			score int64
		}
		rows := make([]row, 0, len(s.players))
		global := chat == 0 || strings.Contains(" "+args+" ", " global ")
		for _, other := range s.players {
			inChat := global
			for _, c := range other.Chats {
				if c == chat {
					inChat = true
					break
				}
			}
			if !inChat {
				continue
			}
			score := other.coins()
			if metric == "wins" {
				score = other.Stats["wins"]
			} else if metric == "level" {
				score = int64(other.Level)
			}
			rows = append(rows, row{other.ID, other.Name, score})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].score == rows[j].score {
				return rows[i].id < rows[j].id
			}
			return rows[i].score > rows[j].score
		})
		var out strings.Builder
		scope := "This group"
		if global {
			scope = "Global"
		}
		fmt.Fprintf(&out, "🏆 <b>%s · %s</b>\n", scope, metric)
		for i, r := range rows[:min(10, len(rows))] {
			fmt.Fprintf(&out, "%d. %s — %d\n", i+1, html.EscapeString(gameName(r.name)), r.score)
		}
		out.WriteString("\n/lb [coins|wins|level] [global]")
		return out.String(), nil
	default:
		return fmt.Sprintf("🎮 <b>%s</b> · Level %d\n🪙 %d coins · %d XP · %d wins\n⚔️ %s · Lv%d\n\n/daily · /battle · /shop · /lb\n/fighters · /equip &lt;id&gt; · /upgrade\nChallenge a friend with /fight as a reply or /fight @username.", html.EscapeString(p.Name), p.Level, p.coins(), p.XP, p.Stats["wins"], html.EscapeString(p.active().Char), p.active().Level), nil
	}
}

func gameCommand(action string) func(*tg.NewMessage) error {
	return func(m *tg.NewMessage) error {
		if m.Sender == nil || m.Sender.Bot || m.SenderID() <= 0 {
			return nil
		}
		chat := m.ChatID()
		if m.IsPrivate() {
			chat = 0
		}
		text, err := game.action(m.SenderID(), m.Sender.FirstName, chat, action, m.Args(), time.Now().Unix())
		if err != nil {
			text = html.EscapeString(err.Error())
		}
		_, err = m.Reply(text, &tg.SendOptions{ReplyMarkup: gameMenu(m.SenderID())})
		return err
	}
}

func GameActionCallback(cb *tg.CallbackQuery) error {
	parts := strings.SplitN(cb.DataString(), ":", 3)
	if len(parts) != 3 {
		return nil
	}
	id, _ := strconv.ParseInt(parts[1], 10, 64)
	if id <= 0 || id != cb.SenderID {
		_, err := cb.Answer("Open /game to use your own buttons.", &tg.CallbackOptions{Alert: true})
		return err
	}
	command := map[string]string{"daily": "daily", "battle": "battle", "shop": "shop", "lb": "lb"}[parts[2]]
	if command == "" {
		return nil
	}
	if modules.CallbackCommandDisabled(cb, command) {
		_, err := cb.Answer("This command is disabled here.")
		return err
	}
	cb.Answer("")
	chat := cb.GetChatID()
	if cb.IsPrivate() {
		chat = 0
	}
	name := ""
	if cb.Sender != nil {
		name = cb.Sender.FirstName
	}
	text, err := game.action(id, name, chat, parts[2], "", time.Now().Unix())
	if err != nil {
		text = html.EscapeString(err.Error())
	}
	_, err = cb.Edit(text, &tg.SendOptions{ReplyMarkup: gameMenu(id)})
	return err
}

func GameFightHandler(m *tg.NewMessage) error {
	if m.Sender == nil || m.Sender.Bot || m.SenderID() <= 0 {
		return nil
	}
	t, _, err := modules.ResolveTarget(m)
	if err != nil || t == nil || t.IsChannel || t.ID <= 0 || t.ID == m.SenderID() || (t.User != nil && t.User.Bot) {
		_, err = m.Reply("Reply to a friend with /fight, or use /fight @username.")
		return err
	}
	game.mu.Lock()
	if !game.loaded {
		game.mu.Unlock()
		return nil
	}
	now := time.Now().Unix()
	for id, ch := range game.challenges {
		if ch.Expires < now {
			delete(game.challenges, id)
		}
	}
	if len(game.challenges) >= 1000 {
		game.mu.Unlock()
		_, err = m.Reply("The arena is busy. Try again shortly.")
		return err
	}
	chat := m.ChatID()
	if m.IsPrivate() {
		chat = 0
	}
	game.player(m.SenderID(), m.Sender.FirstName, chat)
	ch := gameChallenge{ID: rand.Uint64(), From: m.SenderID(), To: t.ID, Name: t.Name, Expires: now + 300}
	game.challenges[ch.From] = ch
	game.mu.Unlock()
	kb := tg.NewKeyboard().AddRow(tg.Button.Data("⚔️ Accept", fmt.Sprintf("jfight:%d:%d", ch.From, ch.ID))).Build()
	_, err = m.Reply(fmt.Sprintf("⚔️ %s, %s challenged you!\nAccept within 5 minutes. No wager; both players earn XP.", t.Mention(), html.EscapeString(m.Sender.FirstName)), &tg.SendOptions{ReplyMarkup: kb})
	return err
}

func GameFightCallback(cb *tg.CallbackQuery) error {
	if modules.CallbackCommandDisabled(cb, "fight") {
		_, err := cb.Answer("This command is disabled here.")
		return err
	}
	parts := strings.Split(cb.DataString(), ":")
	if len(parts) != 3 {
		return nil
	}
	from, _ := strconv.ParseInt(parts[1], 10, 64)
	token, _ := strconv.ParseUint(parts[2], 10, 64)
	game.mu.Lock()
	ch, ok := game.challenges[from]
	if !ok || ch.ID != token || ch.Expires < time.Now().Unix() {
		game.mu.Unlock()
		_, err := cb.Answer("This challenge expired. Send /fight again.", &tg.CallbackOptions{Alert: true})
		return err
	}
	if ch.To != cb.SenderID {
		game.mu.Unlock()
		_, err := cb.Answer("Only the challenged player can accept.", &tg.CallbackOptions{Alert: true})
		return err
	}
	chat := cb.GetChatID()
	if cb.IsPrivate() {
		chat = 0
	}
	b := game.player(ch.To, ch.Name, chat)
	a := game.players[ch.From]
	text, err := gameBattle(a, b, time.Now().Unix(), rand.IntN)
	if err == nil {
		delete(game.challenges, from)
		game.mark(a.ID)
		game.mark(b.ID)
	}
	game.mu.Unlock()
	if err != nil {
		_, e := cb.Answer(err.Error(), &tg.CallbackOptions{Alert: true})
		return e
	}
	cb.Answer("")
	_, err = cb.Edit(text, &tg.SendOptions{ReplyMarkup: tg.NewKeyboard().Build()})
	return err
}

func init() {
	modules.QueueHandlerRegistration(func() {
		for _, action := range []string{"game", "bal", "balance", "profile", "daily", "battle", "spar", "shop", "buy", "upgrade", "fighters", "equip", "lb", "leaderboard"} {
			modules.OnCommand(modules.Client, "cmd:"+action, gameCommand(action))
		}
		modules.OnCommand(modules.Client, "cmd:fight", GameFightHandler)
		modules.Client.On("callback:jg:", GameActionCallback)
		modules.Client.On("callback:jfight:", GameFightCallback)
	})
	modules.Mods.AddModule("Game", `<b>🎮 Julia Game</b>
/game — Your profile and quick buttons
/daily — Coins, XP and a daily streak
/battle — A quick fight against an arena rival
/fight — Challenge a friend by reply or username
/shop · /buy — Recruit fighters
/fighters · /equip &lt;id&gt; · /upgrade — Choose and improve your fighter
/lb [coins|wins|level] [global] — Leaderboards

New players get 1,000 coins and a starter fighter. Battles have a 90-second cooldown. Win or lose, you earn coins and XP.`)
}
