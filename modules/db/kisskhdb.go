package db

import (
	"encoding/json"
	"main/internal/kisskh"
	"main/internal/mongostore"
)

var kissWatchBucket = []byte("kisskh_watch")
var kissWatchKey = []byte("singleton")

func ReadKissWatch() (kisskh.WatchState, error) {
	var state kisskh.WatchState
	state.Init()
	d, e := GetDB()
	if e != nil {
		return state, e
	}
	e = d.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket(kissWatchBucket)
		if b == nil {
			return nil
		}
		raw := b.Get(kissWatchKey)
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &state)
	})
	state.Init()
	return state, e
}
func UpdateKissWatch(fn func(*kisskh.WatchState) error) error {
	d, e := GetDB()
	if e != nil {
		return e
	}
	return d.Update(func(tx *mongostore.Tx) error {
		b, e := tx.CreateBucketIfNotExists(kissWatchBucket)
		if e != nil {
			return e
		}
		var state kisskh.WatchState
		if raw := b.Get(kissWatchKey); raw != nil {
			if e = json.Unmarshal(raw, &state); e != nil {
				return e
			}
		}
		state.Init()
		if e = fn(&state); e != nil {
			return e
		}
		raw, e := json.Marshal(state)
		if e != nil {
			return e
		}
		return b.Put(kissWatchKey, raw)
	})
}
