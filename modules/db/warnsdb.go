package db

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"main/internal/mongostore"
)

type WarnAction string

const (
	WarnActionBan   WarnAction = "ban"
	WarnActionMute  WarnAction = "mute"
	WarnActionKick  WarnAction = "kick"
	WarnActionTBan  WarnAction = "tban"
	WarnActionTMute WarnAction = "tmute"
)

const DefaultMaxWarns = 3

type Warn struct {
	ID        string    `json:"id"`
	Reason    string    `json:"reason"`
	AdminID   int64     `json:"admin_id"`
	Timestamp time.Time `json:"timestamp"`
	ExpiresAt int64     `json:"expires_at,omitempty"`
}

type WarnSettings struct {
	MaxWarns       int        `json:"max_warns"`
	Action         WarnAction `json:"action"`
	DecayDays      int        `json:"decay_days"`
	ActionDuration int64      `json:"action_duration,omitempty"`
}

var (
	warnsBucketsReady bool
	warnsBucketsMu    sync.Mutex
	warnSettingsCache sync.Map
)

func ensureWarnsBuckets(db *mongostore.DB) error {
	warnsBucketsMu.Lock()
	defer warnsBucketsMu.Unlock()
	if warnsBucketsReady {
		return nil
	}
	err := db.Update(func(tx *mongostore.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte("warns")); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists([]byte("warns_settings"))
		return err
	})
	warnsBucketsReady = err == nil
	return err
}

func warnsDB() (*mongostore.DB, error) {
	d, err := GetDB()
	if err != nil {
		return nil, err
	}
	return d, ensureBucketsOnce("warns", d, ensureWarnsBuckets)
}

func userWarnBucket(tx *mongostore.Tx, chatID, userID int64) *mongostore.Bucket {
	b := tx.Bucket([]byte("warns"))
	if b == nil {
		return nil
	}
	cb := b.Bucket([]byte(strconv.FormatInt(chatID, 10)))
	if cb == nil {
		return nil
	}
	return cb.Bucket([]byte(strconv.FormatInt(userID, 10)))
}

// AddWarn stores warn (assigning an ID when empty) and returns the number of stored warns for the user.
func AddWarn(chatID, userID int64, warn *Warn) (int, error) {
	db, err := warnsDB()
	if err != nil {
		return 0, err
	}
	var count int
	err = db.Update(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte("warns"))
		cb, err := b.CreateBucketIfNotExists([]byte(strconv.FormatInt(chatID, 10)))
		if err != nil {
			return err
		}
		ub, err := cb.CreateBucketIfNotExists([]byte(strconv.FormatInt(userID, 10)))
		if err != nil {
			return err
		}
		id, err := ub.NextSequence()
		if err != nil {
			return err
		}
		if warn.ID == "" {
			warn.ID = strconv.FormatUint(id, 10)
		}
		data, err := json.Marshal(warn)
		if err != nil {
			return err
		}
		if err := ub.Put(itob(int(id)), data); err != nil {
			return err
		}
		count = ub.Stats().KeyN
		return nil
	})
	return count, err
}

func GetWarns(chatID, userID int64) ([]*Warn, error) {
	db, err := warnsDB()
	if err != nil {
		return nil, err
	}
	var warns []*Warn
	err = db.View(func(tx *mongostore.Tx) error {
		ub := userWarnBucket(tx, chatID, userID)
		if ub == nil {
			return nil
		}
		c := ub.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var w Warn
			if json.Unmarshal(v, &w) == nil {
				warns = append(warns, &w)
			}
		}
		return nil
	})
	return warns, err
}

// RemoveWarns deletes every stored warn of the user for which match returns true and returns how many were removed.
func RemoveWarns(chatID, userID int64, match func(*Warn) bool) (int, error) {
	db, err := warnsDB()
	if err != nil {
		return 0, err
	}
	removed := 0
	err = db.Update(func(tx *mongostore.Tx) error {
		ub := userWarnBucket(tx, chatID, userID)
		if ub == nil {
			return nil
		}
		c := ub.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var w Warn
			if json.Unmarshal(v, &w) != nil || !match(&w) {
				continue
			}
			if err := c.Delete(); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}

func RemoveWarnByID(chatID, userID int64, id string) (bool, error) {
	n, err := RemoveWarns(chatID, userID, func(w *Warn) bool { return w.ID == id })
	return n > 0, err
}

func ResetWarns(chatID, userID int64) error {
	db, err := warnsDB()
	if err != nil {
		return err
	}
	err = db.Update(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte("warns"))
		if b == nil {
			return nil
		}
		cb := b.Bucket([]byte(strconv.FormatInt(chatID, 10)))
		if cb == nil {
			return nil
		}
		return cb.DeleteBucket([]byte(strconv.FormatInt(userID, 10)))
	})
	if err == mongostore.ErrBucketNotFound {
		return nil
	}
	return err
}

func SetWarnSettings(chatID int64, settings *WarnSettings) error {
	db, err := warnsDB()
	if err != nil {
		return err
	}
	err = db.Update(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte("warns_settings"))
		data, err := json.Marshal(settings)
		if err != nil {
			return err
		}
		return b.Put([]byte(strconv.FormatInt(chatID, 10)), data)
	})
	if err == nil {
		cp := *settings
		warnSettingsCache.Store(chatID, &cp)
	}
	return err
}

// GetWarnSettings always returns usable settings (defaults on error); the result is a private copy.
func GetWarnSettings(chatID int64) (*WarnSettings, error) {
	if v, ok := warnSettingsCache.Load(chatID); ok {
		cp := *v.(*WarnSettings)
		return &cp, nil
	}
	settings := &WarnSettings{MaxWarns: DefaultMaxWarns, Action: WarnActionBan}
	db, err := warnsDB()
	if err != nil {
		return settings, err
	}
	err = db.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket([]byte("warns_settings"))
		if b == nil {
			return nil
		}
		data := b.Get([]byte(strconv.FormatInt(chatID, 10)))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, settings)
	})
	if settings.MaxWarns < 1 {
		settings.MaxWarns = DefaultMaxWarns
	}
	if settings.Action == "" {
		settings.Action = WarnActionBan
	}
	if err == nil {
		cp := *settings
		warnSettingsCache.Store(chatID, &cp)
	}
	return settings, err
}

func itob(v int) []byte {
	b := make([]byte, 8)
	for i := range uint(8) {
		b[7-i] = byte(v >> (i * 8))
	}
	return b
}
