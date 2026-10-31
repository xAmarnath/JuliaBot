package kisskh

import "sort"

// WatchState is one shared, persistent subscription list, not per-user subscriptions.
type WatchState struct {
	BootstrapDone bool                  `json:"bootstrap_done"`
	ChannelID     int64                 `json:"channel_id"`
	Dramas        map[int64]*WatchDrama `json:"dramas"`
}
type WatchDrama struct {
	Drama       Drama                   `json:"drama"`
	Episodes    map[int64]*WatchEpisode `json:"episodes"`
	LastChecked int64                   `json:"last_checked"`
	LastError   string                  `json:"last_error,omitempty"`
}
type WatchEpisode struct {
	RetryAt   int64   `json:"retry_at,omitempty"`
	Episode   Episode `json:"episode"`
	State     string  `json:"state"` // baseline, pending, downloading, delivering, sent, uncertain
	MessageID int32   `json:"message_id,omitempty"`
	ChannelID int64   `json:"channel_id,omitempty"`
}

func (s *WatchState) Init() {
	if s.Dramas == nil {
		s.Dramas = make(map[int64]*WatchDrama)
	}
}
func (s *WatchState) Add(d Drama) bool {
	s.Init()
	if _, exists := s.Dramas[d.ID]; exists {
		return false
	}
	w := &WatchDrama{Drama: d, Episodes: make(map[int64]*WatchEpisode)}
	for _, e := range d.Episodes {
		if e.ID > 0 {
			w.Episodes[e.ID] = &WatchEpisode{Episode: e, State: func() string {
				if e.Released || e.Sub > 0 {
					return "baseline"
				}
				return "waiting"
			}()}
		}
	}
	s.Dramas[d.ID] = w
	return true
}
func (w *WatchDrama) Observe(d Drama, now int64) {
	if w.Episodes == nil {
		w.Episodes = make(map[int64]*WatchEpisode)
	}
	for _, e := range d.Episodes {
		if e.ID > 0 && w.Episodes[e.ID] == nil {
			w.Episodes[e.ID] = &WatchEpisode{Episode: e, State: func() string {
				if e.Released || e.Sub > 0 {
					return "pending"
				}
				return "waiting"
			}()}
		}
	}
	for _, e := range d.Episodes {
		if current := w.Episodes[e.ID]; current != nil && current.State == "waiting" && (e.Released || e.Sub > 0) {
			current.State = "pending"
			current.Episode = e
		}
	}
	w.Drama = d
	w.LastChecked = now
	w.LastError = ""
}
func (w *WatchDrama) Pending() []Episode {
	out := []Episode{}
	for _, e := range w.Episodes {
		if e.State == "pending" {
			out = append(out, e.Episode)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Number == out[j].Number {
			return out[i].ID < out[j].ID
		}
		return out[i].Number < out[j].Number
	})
	return out
}

// A restart during delivery is ambiguous: require explicit admin retry to avoid duplicate posts.
func (s *WatchState) Recover() {
	for _, w := range s.Dramas {
		for _, e := range w.Episodes {
			switch e.State {
			case "downloading":
				e.State = "pending"
			case "delivering":
				e.State = "uncertain"
			}
		}
	}
}
