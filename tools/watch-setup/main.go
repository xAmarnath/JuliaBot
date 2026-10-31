// Local deployment helper: no Telegram session, no episode download, no credentials in output.
package main

import (
	"context"
	"fmt"
	"log"
	"main/internal/kisskh"
	"main/modules/db"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "status" && os.Args[1] != "apply") {
		log.Fatal("usage: watch-setup status|apply (apply replaces the configured watch channel and seeds drama 13907)")
	}
	if len(os.Args) > 1 && os.Args[1] == "status" {
		s, e := db.ReadKissWatch()
		if e != nil {
			log.Fatal(e)
		}
		fmt.Printf("Channel=%d, watched=%d\n", s.ChannelID, len(s.Dramas))
		for id, w := range s.Dramas {
			counts := map[string]int{}
			for _, ep := range w.Episodes {
				counts[ep.State]++
			}
			fmt.Printf("Drama=%d states=%v last_checked=%d\n", id, counts, w.LastChecked)
		}
		_ = db.CloseDB()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	api := kisskh.New()
	d, e := api.Drama(ctx, 13907)
	if e != nil {
		log.Fatal(e)
	}
	if e = api.CheckReleases(ctx, d); e != nil {
		log.Fatal(e)
	}
	released := 0
	for _, ep := range d.Episodes {
		if ep.Released {
			released++
		}
		if ep.Number >= 14 {
			fmt.Printf("Episode %g: released=%v, subtitles=%d\n", ep.Number, ep.Released, ep.Sub)
		}
	}
	dir, e := os.MkdirTemp("", "kisskh-poster-probe-")
	if e != nil {
		log.Fatal(e)
	}
	defer os.RemoveAll(dir)
	if e = api.PosterThumbnail(ctx, d.Thumbnail, filepath.Join(dir, "poster.jpg")); e != nil {
		log.Fatal(e)
	}
	fmt.Println("Live poster thumbnail: passed")
	if e = db.UpdateKissWatch(func(s *kisskh.WatchState) error {
		s.ChannelID = -1003695619798
		s.Add(*d)
		s.BootstrapDone = true
		return nil
	}); e != nil {
		log.Fatal(e)
	}
	saved, e := db.ReadKissWatch()
	if e != nil {
		log.Fatal(e)
	}
	w := saved.Dramas[13907]
	if w == nil || len(w.Pending()) != 0 {
		log.Fatal("unexpected initial queue")
	}
	fmt.Printf("Saved watch channel=%d, drama=13907, released baseline=%d, waiting=%d, pending=%d\n", saved.ChannelID, released, len(d.Episodes)-released, len(w.Pending()))
	if e = db.CloseDB(); e != nil {
		log.Fatal(e)
	}
}
