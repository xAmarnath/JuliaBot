package extras

import (
	"context"
	"errors"
	"fmt"
	tg "github.com/xAmarnath/gogram/telegram"
	"html"
	"log"
	"main/internal/kisskh"
	"main/modules"
	"main/modules/db"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const kissWatchInterval = 30 * time.Minute

var kissWatchOnce sync.Once

func kissWatchAdmin(m *tg.NewMessage) bool { return modules.IsTransferUser(m.SenderID()) }
func kissReply(m *tg.NewMessage, text string) error {
	_, e := m.Reply(text, &tg.SendOptions{ParseMode: tg.HTML})
	return e
}
func kissWatchIDs(s kisskh.WatchState) []int64 {
	ids := []int64{}
	for id := range s.Dramas {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
func KissChannelHandler(m *tg.NewMessage) error {
	if !kissWatchAdmin(m) {
		return kissReply(m, "Only bot admins can change the shared watch channel.")
	}
	target := strings.TrimSpace(m.Args())
	if target == "" {
		s, e := db.ReadKissWatch()
		if e != nil {
			return e
		}
		return kissReply(m, fmt.Sprintf("Watch channel: <code>%d</code>\nSet with /kisschannel &lt;channel ID or @username&gt;. The bot needs Post Messages permission.", s.ChannelID))
	}
	var peerTarget any = target
	if id, e := strconv.ParseInt(target, 10, 64); e == nil {
		peerTarget = id
	}
	peer, e := m.Client.ResolvePeer(peerTarget)
	if e != nil {
		return kissReply(m, "Could not resolve that channel. Add the bot as an admin first.")
	}
	channel, ok := peer.(*tg.InputPeerChannel)
	if !ok {
		return kissReply(m, "The destination must be a channel.")
	}
	c, e := m.Client.GetChannel(channel.ChannelID)
	if e != nil || !c.Broadcast {
		return kissReply(m, "The destination must be a broadcast channel.")
	}
	member, e := m.Client.GetChatMember(peer, m.Client.Me().ID)
	if e != nil || !(member.Status == tg.Creator || (member.Status == tg.Admin && member.Rights != nil && member.Rights.PostMessages)) {
		return kissReply(m, "Give the bot Post Messages permission in that channel.")
	}
	id := m.Client.GetPeerID(peer)
	if e = db.UpdateKissWatch(func(s *kisskh.WatchState) error { s.ChannelID = id; return nil }); e != nil {
		return e
	}
	return kissReply(m, fmt.Sprintf("Shared watch channel set to <code>%d</code>. New episodes are checked every 30 minutes.", id))
}
func KissWatchHandler(m *tg.NewMessage) error {
	if !kissWatchAdmin(m) {
		return kissReply(m, "Only bot admins can manage the shared watchlist.")
	}
	fields := strings.Fields(m.Args())
	if len(fields) == 0 || fields[0] == "list" {
		state, e := db.ReadKissWatch()
		if e != nil {
			return e
		}
		var text strings.Builder
		fmt.Fprintf(&text, "<b>KissKH watchlist</b>\nChannel: <code>%d</code>\nCheck interval: 30 minutes\n", state.ChannelID)
		for _, id := range kissWatchIDs(state) {
			w := state.Dramas[id]
			uncertain := 0
			waiting := 0
			for _, ep := range w.Episodes {
				if ep.State == "waiting" {
					waiting++
				}
				if ep.State == "uncertain" || ep.State == "delivering" {
					uncertain++
				}
			}
			fmt.Fprintf(&text, "\n<code>%d</code> · %s\nPending: %d · Needs review: %d", id, html.EscapeString(w.Drama.Title), len(w.Pending()), uncertain)
			if w.LastError != "" {
				fmt.Fprintf(&text, "\nLast check: %s", html.EscapeString(w.LastError))
			}
		}
		text.WriteString("\n\n/kisswatch add &lt;ID, URL or name&gt;\n/kisswatch remove &lt;ID&gt;\n/kisswatch retry &lt;drama ID&gt; &lt;episode ID&gt;\n/kisschannel &lt;channel ID or @username&gt;\nAdding a drama watches future episodes only. Retry only after checking the channel for duplicates.")
		return kissReply(m, text.String())
	}
	if len(fields) < 2 {
		return kissReply(m, "Use /kisswatch add &lt;drama&gt; or /kisswatch remove &lt;ID&gt;.")
	}
	switch strings.ToLower(fields[0]) {
	case "add":
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		query := strings.Join(fields[1:], " ")
		id, ok := kisskh.DramaID(query)
		if !ok {
			results, e := kissAPI.Search(ctx, query)
			if e != nil {
				return kissReply(m, "Search failed; try again later.")
			}
			if len(results) != 1 {
				var text strings.Builder
				text.WriteString("Use a drama ID to choose an exact match:\n")
				for i, d := range results {
					if i == 10 {
						break
					}
					fmt.Fprintf(&text, "<code>%d</code> · %s\n", d.ID, html.EscapeString(d.Title))
				}
				return kissReply(m, text.String())
			}
			id = results[0].ID
		}
		drama, e := kissAPI.Drama(ctx, id)
		if e != nil {
			return kissReply(m, "Could not load that drama. Nothing was added.")
		}
		if e = kissAPI.CheckReleases(ctx, drama); e != nil {
			return kissReply(m, "Could not verify episode availability. Nothing was added; please retry.")
		}
		added := false
		e = db.UpdateKissWatch(func(s *kisskh.WatchState) error {
			if len(s.Dramas) >= 30 && s.Dramas[id] == nil {
				return errors.New("watchlist limit is 30 dramas")
			}
			added = s.Add(*drama)
			return nil
		})
		if e != nil {
			return e
		}
		if !added {
			return kissReply(m, "That drama is already watched; its delivery history was kept.")
		}
		return kissReply(m, fmt.Sprintf("Watching <b>%s</b> (<code>%d</code>). %d existing episodes skipped; new episodes will upload automatically. Checks run every 30 minutes.", html.EscapeString(drama.Title), id, releasedEpisodeCount(*drama)))
	case "remove":
		id, ok := kisskh.DramaID(fields[1])
		if !ok {
			return kissReply(m, "Enter a valid drama ID.")
		}
		e := db.UpdateKissWatch(func(s *kisskh.WatchState) error { delete(s.Dramas, id); return nil })
		if e != nil {
			return e
		}
		return kissReply(m, "Drama removed from the shared watchlist.")
	case "retry":
		if len(fields) != 3 {
			return kissReply(m, "Use /kisswatch retry &lt;drama ID&gt; &lt;episode ID&gt;. Check the channel first to avoid duplicates.")
		}
		id, _ := strconv.ParseInt(fields[1], 10, 64)
		epid, _ := strconv.ParseInt(fields[2], 10, 64)
		e := db.UpdateKissWatch(func(s *kisskh.WatchState) error {
			w := s.Dramas[id]
			if w == nil || w.Episodes[epid] == nil {
				return errors.New("episode not found")
			}
			ep := w.Episodes[epid]
			if ep.State != "uncertain" {
				return errors.New("only an uncertain delivery can be manually retried")
			}
			ep.State = "pending"
			ep.RetryAt = 0
			w.LastChecked = 0
			return nil
		})
		if e != nil {
			return kissReply(m, html.EscapeString(e.Error()))
		}
		return kissReply(m, "Episode queued for retry on the next scheduler tick.")
	default:
		return kissReply(m, "Use /kisswatch list, add, remove or retry.")
	}
}

func StartKissWatch(ctx context.Context) {
	kissWatchOnce.Do(func() {
		go func() {
			for {
				e := db.UpdateKissWatch(func(s *kisskh.WatchState) error {
					s.Recover()
					if s.ChannelID == 0 {
						if id, e := strconv.ParseInt(os.Getenv("KISSKH_WATCH_CHANNEL"), 10, 64); e == nil && id < 0 {
							s.ChannelID = id
						}
					}
					return nil
				})
				if e == nil {
					break
				}
				log.Printf("[kisskh watch] initialization failed: %v", e)
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Minute):
				}
			}
			for {
				if err := bootstrapKissWatch(ctx); err == nil {
					break
				} else {
					log.Printf("[kisskh watch] bootstrap failed: %v", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Minute):
				}
			}
			log.Printf("[kisskh watch] ready; interval=30m, one shared watchlist")
			go runKissWatchDownloads(ctx)
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				checkKissWatch(ctx)
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	})
}
func checkKissWatch(ctx context.Context) {
	state, e := db.ReadKissWatch()
	if e != nil {
		log.Printf("[kisskh watch] read failed: %v", e)
		return
	}
	if state.ChannelID == 0 {
		return
	}
	for _, id := range kissWatchIDs(state) {
		if ctx.Err() != nil {
			return
		}
		w := state.Dramas[id]
		if time.Now().Unix()-w.LastChecked < int64(kissWatchInterval/time.Second) {
			continue
		}
		lookup, cancel := context.WithTimeout(ctx, time.Minute)
		drama, e := kissAPI.Drama(lookup, id)
		if e == nil {
			e = kissAPI.CheckReleases(lookup, drama)
		}
		cancel()
		if e != nil {
			_ = db.UpdateKissWatch(func(s *kisskh.WatchState) error {
				if current := s.Dramas[id]; current != nil {
					current.LastChecked = time.Now().Unix()
					current.LastError = "Metadata lookup failed; retry in 30 minutes."
				}
				return nil
			})
			continue
		}
		e = db.UpdateKissWatch(func(s *kisskh.WatchState) error {
			if current := s.Dramas[id]; current != nil {
				current.Observe(*drama, time.Now().Unix())
			}
			return nil
		})
		if e != nil {
			log.Printf("[kisskh watch] save failed: %v", e)
			continue
		}
	}
}
func runKissWatchDownloads(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		drainKissWatchDownloads(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func drainKissWatchDownloads(ctx context.Context) {
	state, e := db.ReadKissWatch()
	if e != nil || state.ChannelID == 0 {
		return
	}
	for _, id := range kissWatchIDs(state) {
		w := state.Dramas[id]
		for _, ep := range w.Pending() {
			if ctx.Err() != nil {
				return
			}
			if w.Episodes[ep.ID].RetryAt > time.Now().Unix() {
				continue
			}
			select {
			case kissJobs <- struct{}{}:
			case <-ctx.Done():
				return
			default:
				return
			}
			sendWatchedEpisode(ctx, id, w.Drama, ep)
			<-kissJobs
		}
	}
}

func sendWatchedEpisode(parent context.Context, id int64, drama kisskh.Drama, ep kisskh.Episode) {
	var channel int64
	e := db.UpdateKissWatch(func(s *kisskh.WatchState) error {
		w := s.Dramas[id]
		if w == nil || w.Episodes[ep.ID] == nil || w.Episodes[ep.ID].State != "pending" || s.ChannelID == 0 {
			return errors.New("subscription changed")
		}
		channel = s.ChannelID
		w.Episodes[ep.ID].State = "downloading"
		return nil
	})
	if e != nil {
		return
	}
	delivering := false
	status, e := modules.Client.SendMessage(channel, fmt.Sprintf("Preparing %s - episode %g...", html.EscapeString(drama.Title), ep.Number), &tg.SendOptions{ParseMode: tg.HTML, Silent: true})
	var result *tg.NewMessage
	if e == nil {
		ctx, cancel := context.WithTimeout(modules.WithTransferAccount(parent), 2*time.Hour)
		result, e = deliverKissEpisode(ctx, status, drama, ep, func() error {
			err := db.UpdateKissWatch(func(s *kisskh.WatchState) error {
				w := s.Dramas[id]
				if w == nil || s.ChannelID != channel || w.Episodes[ep.ID] == nil || w.Episodes[ep.ID].State != "downloading" {
					return errors.New("subscription changed while downloading")
				}
				w.Episodes[ep.ID].State = "delivering"
				w.Episodes[ep.ID].ChannelID = channel
				return nil
			})
			if err == nil {
				delivering = true
			}
			return err
		})
		cancel()
	}
	if e != nil && status != nil {
		_, _ = status.Delete()
	}
	saveErr := db.UpdateKissWatch(func(s *kisskh.WatchState) error {
		w := s.Dramas[id]
		if w == nil {
			return nil
		}
		entry := w.Episodes[ep.ID]
		if entry == nil || (entry.State != "downloading" && entry.State != "delivering") {
			return nil
		}
		if e == nil && result != nil {
			entry.State = "sent"
			entry.MessageID = result.ID
			entry.ChannelID = channel
			w.LastError = ""
		} else if delivering {
			entry.State = "uncertain"
			w.LastError = fmt.Sprintf("Episode %g (ID %d): delivery uncertain; inspect channel before /kisswatch retry.", ep.Number, ep.ID)
		} else {
			entry.State = "pending"
			entry.RetryAt = time.Now().Add(kissWatchInterval).Unix()
			w.LastError = fmt.Sprintf("Episode %g: download/poster/channel preparation failed; retry in 30 minutes.", ep.Number)
		}
		return nil
	})
	if saveErr != nil {
		log.Printf("[kisskh watch] delivery state save failed: %v", saveErr)
	}
}
func init() {
	modules.QueueHandlerRegistration(func() {
		modules.OnCommand(modules.Client, "cmd:kisswatch", KissWatchHandler)
		modules.OnCommand(modules.Client, "cmd:kisschannel", KissChannelHandler)
	})
}

func releasedEpisodeCount(d kisskh.Drama) int {
	n := 0
	for _, e := range d.Episodes {
		if e.Sub > 0 || e.Released {
			n++
		}
	}
	return n
}

func bootstrapKissWatch(ctx context.Context) error {
	state, err := db.ReadKissWatch()
	if err != nil {
		return err
	}
	if state.BootstrapDone {
		return nil
	}
	id, _ := strconv.ParseInt(os.Getenv("KISSKH_WATCH_BOOTSTRAP_DRAMA"), 10, 64)
	var drama *kisskh.Drama
	if id > 0 {
		lookup, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		drama, err = kissAPI.Drama(lookup, id)
		if err != nil {
			return err
		}
		if err = kissAPI.CheckReleases(lookup, drama); err != nil {
			return err
		}
	}
	return db.UpdateKissWatch(func(s *kisskh.WatchState) error {
		if s.BootstrapDone {
			return nil
		}
		if drama != nil {
			s.Add(*drama)
			log.Printf("[kisskh watch] initialized drama %d: %d released episodes baselined, %d waiting", drama.ID, releasedEpisodeCount(*drama), len(drama.Episodes)-releasedEpisodeCount(*drama))
		}
		s.BootstrapDone = true
		return nil
	})
}
