package extras

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testPlayer(id int64) *Player {
	p := &Player{ID: id, Name: "Player", Wallet: 1000}
	p.prepare()
	return p
}

func TestGameLegacyProgress(t *testing.T) {
	raw := []byte(`{"id":5,"name":"Old player","wallet":100,"bank":2000,"gems":7,"level":4,"next_id":19,"fighters":[{"id":9,"char":"Wolf","rarity":3,"level":5,"xp":17,"wins":2}],"active_fighter":9,"items":{"potion":3},"estates":[1,2],"duel":{"Players":[5,6],"Wager":250,"Done":false}}`)
	var p Player
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	p.prepare()
	p.prepare()
	if p.Wallet != 350 || p.Bank != 2000 || p.active().XP != 17 || p.NextID != 19 {
		t.Fatalf("progress lost or escrow refunded twice: %+v", p)
	}
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(out, &fields)
	if string(fields["items"]) != `{"potion":3}` || string(fields["estates"]) != "[1,2]" || fields["duel"] != nil {
		t.Fatalf("legacy fields: %s", out)
	}
	var restored Player
	_ = json.Unmarshal(out, &restored)
	restored.prepare()
	if restored.Wallet != 350 {
		t.Fatal("restart refunded escrow again")
	}
}

func TestGameDailyShopBattle(t *testing.T) {
	p := testPlayer(1)
	const now int64 = 1700000000
	if _, err := gameDaily(p, now); err != nil {
		t.Fatal(err)
	}
	wallet := p.Wallet
	if _, err := gameDaily(p, now+86399); err == nil || p.Wallet != wallet {
		t.Fatal("duplicate daily reward")
	}
	_, _ = gameDaily(p, now+86400)
	if p.DailyStreak != 2 {
		t.Fatal("daily streak")
	}
	_, _ = gameDaily(p, now+4*86400)
	if p.DailyStreak != 1 {
		t.Fatal("streak reset")
	}
	p.Wallet, p.Bank = 100, 700
	if _, err := gameBuy(p, "scout"); err != nil {
		t.Fatal(err)
	}
	if p.coins() != 0 || p.active().Char != "Scout" {
		t.Fatal("bank balance not spendable")
	}
	if _, err := gameBuy(p, "scout"); err == nil {
		t.Fatal("duplicate fighter")
	}
	q := testPlayer(2)
	p.active().Level = 100
	if _, err := gameBattle(p, q, now, func(int) int { return 50 }); err != nil {
		t.Fatal(err)
	}
	if p.Stats["wins"] != 1 || q.Stats["losses"] != 1 || p.Wallet != 150 || q.Wallet != 1025 {
		t.Fatal("battle rewards")
	}
	if _, err := gameBattle(p, q, now+89, func(int) int { return 50 }); err == nil || p.Stats["wins"] != 1 {
		t.Fatal("battle cooldown")
	}
	if _, err := gameBattle(p, p, now+90, func(int) int { return 50 }); err == nil {
		t.Fatal("self battle")
	}
}

func TestGameFlushRetainsConcurrentAndFailedWrites(t *testing.T) {
	s := &gameStore{players: map[int64]*Player{1: testPlayer(1)}, dirty: map[int64]uint64{}}
	s.mark(1)
	failure := errors.New("offline")
	if err := s.flush(func(map[int64][]byte) error { return failure }); !errors.Is(err, failure) || len(s.dirty) != 1 {
		t.Fatal("failed flush discarded change")
	}
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.flush(func(data map[int64][]byte) error {
			var saved Player
			_ = json.Unmarshal(data[1], &saved)
			if saved.Wallet != 1000 {
				t.Error("snapshot mutated")
			}
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	s.mu.Lock()
	s.players[1].Wallet = 1200
	s.mark(1)
	s.mu.Unlock()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(s.dirty) != 1 {
		t.Fatal("concurrent change marked saved")
	}
	if err := s.flush(func(data map[int64][]byte) error {
		if !strings.Contains(string(data[1]), `"wallet":1200`) {
			t.Error("latest state missing")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(s.dirty) != 0 {
		t.Fatal("successful flush left dirty state")
	}
}
