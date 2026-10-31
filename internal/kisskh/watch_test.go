package kisskh

import (
	"encoding/json"
	"testing"
)

func TestListedUpcomingEpisodeBecomesDownloadWhenReleased(t *testing.T) {
	s := WatchState{}
	d := Drama{ID: 13907, Episodes: []Episode{{ID: 227225, Number: 14, Sub: 5}, {ID: 227445, Number: 15}, {ID: 227446, Number: 16}}}
	s.Add(d)
	w := s.Dramas[d.ID]
	if w.Episodes[227225].State != "baseline" || w.Episodes[227445].State != "waiting" || len(w.Pending()) != 0 {
		t.Fatal("incorrect release baseline")
	}
	w.Observe(d, 100)
	if len(w.Pending()) != 0 {
		t.Fatal("countdown downloaded")
	}
	d.Episodes[1].Sub = 5
	w.Observe(d, 200)
	if len(w.Pending()) != 1 || w.Pending()[0].Number != 15 {
		t.Fatal("missed episode 15 release")
	}
	w.Episodes[227445].State = "sent"
	w.Observe(d, 300)
	if len(w.Pending()) != 0 {
		t.Fatal("duplicate episode 15")
	}
}

func TestWatchBaselineNewEpisodesAndPersistence(t *testing.T) {
	s := WatchState{}
	d := Drama{ID: 13907, Title: "Show", Episodes: []Episode{{ID: 1, Number: 1, Sub: 1}, {ID: 2, Number: 2, Sub: 1}}}
	if !s.Add(d) || s.Add(d) {
		t.Fatal("subscription idempotence")
	}
	w := s.Dramas[d.ID]
	if len(w.Pending()) != 0 {
		t.Fatal("must skip backlog")
	}
	d.Episodes = []Episode{{ID: 4, Number: 4, Sub: 1}, {ID: 2, Number: 2, Sub: 1}, {ID: 3, Number: 3, Sub: 1}, {ID: 3, Number: 3, Sub: 1}}
	w.Observe(d, 100)
	pending := w.Pending()
	if len(pending) != 2 || pending[0].ID != 3 || pending[1].ID != 4 {
		t.Fatal(pending)
	}
	w.Episodes[3].State = "sent"
	w.Episodes[3].MessageID = 42
	w.Observe(d, 200)
	if len(w.Pending()) != 1 {
		t.Fatal("reposted episode")
	}
	raw, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	var reloaded WatchState
	if e = json.Unmarshal(raw, &reloaded); e != nil {
		t.Fatal(e)
	}
	reloaded.Dramas[d.ID].Observe(d, 300)
	if reloaded.Dramas[d.ID].Episodes[3].MessageID != 42 || len(reloaded.Dramas[d.ID].Pending()) != 1 {
		t.Fatal("history lost on restart")
	}
}
func TestWatchRestartDoesNotRepeatUncertainDelivery(t *testing.T) {
	s := WatchState{}
	s.Add(Drama{ID: 1})
	w := s.Dramas[1]
	w.Episodes[1] = &WatchEpisode{Episode: Episode{ID: 1}, State: "downloading"}
	w.Episodes[2] = &WatchEpisode{Episode: Episode{ID: 2}, State: "delivering"}
	w.Episodes[3] = &WatchEpisode{Episode: Episode{ID: 3}, State: "sent"}
	s.Recover()
	if w.Episodes[1].State != "pending" || w.Episodes[2].State != "uncertain" || w.Episodes[3].State != "sent" {
		t.Fatal("unsafe recovery")
	}
	s.Recover()
	if len(w.Pending()) != 1 {
		t.Fatal("duplicate recovery")
	}
}
