package db

import (
	"encoding/json"
	"strconv"
	"sync"

	"main/internal/mongostore"
)

type BlacklistAction string

const (
	ActionDelete BlacklistAction = "delete"
	ActionBan    BlacklistAction = "ban"
	ActionMute   BlacklistAction = "mute"
	ActionTBan   BlacklistAction = "tban"
	ActionTMute  BlacklistAction = "tmute"
)

type BlacklistSettings struct {
	Action   BlacklistAction `json:"action"`
	Duration string          `json:"duration,omitempty"`
}

type BlacklistEntry struct {
	Word        string `json:"word"`
	FileID      string `json:"file_id,omitempty"`
	MessageLink string `json:"message_link,omitempty"`
	AddedBy     int64  `json:"added_by"`
}

var bucketsReady sync.Map

// ensureBucketsOnce avoids an extra write round-trip on every call once the buckets exist.
func ensureBucketsOnce(name string, db *mongostore.DB, create func(*mongostore.DB) error) error {
	if _, ok := bucketsReady.Load(struct {
		name string
		db   *mongostore.DB
	}{name, db}); ok {
		return nil
	}
	if err := create(db); err != nil {
		return err
	}
	bucketsReady.Store(struct {
		name string
		db   *mongostore.DB
	}{name, db}, true)
	return nil
}

func ensureBlacklistBuckets(db *mongostore.DB) error {
	return db.Update(func(tx *mongostore.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("blacklist"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("blacklist_settings"))
		return err
	})
}

func AddBlacklist(chatID int64, entry *BlacklistEntry) error {
	db, err := GetDB()
	if err != nil {
		return err
	}
	if err := ensureBucketsOnce("blacklist", db, ensureBlacklistBuckets); err != nil {
		return err
	}

	return db.Update(func(tx *mongostore.Tx) error {
		chatsBucket, err := tx.CreateBucketIfNotExists([]byte("blacklist"))
		if err != nil {
			return err
		}
		chatBucket, err := chatsBucket.CreateBucketIfNotExists([]byte(strconv.FormatInt(chatID, 10)))
		if err != nil {
			return err
		}

		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}

		return chatBucket.Put([]byte(entry.Word), data)
	})
}

func RemoveBlacklist(chatID int64, word string) error {
	db, err := GetDB()
	if err != nil {
		return err
	}
	if err := ensureBucketsOnce("blacklist", db, ensureBlacklistBuckets); err != nil {
		return err
	}

	return db.Update(func(tx *mongostore.Tx) error {
		chatsBucket := tx.Bucket([]byte("blacklist"))
		if chatsBucket == nil {
			return nil
		}
		chatBucket := chatsBucket.Bucket([]byte(strconv.FormatInt(chatID, 10)))
		if chatBucket == nil {
			return nil
		}

		return chatBucket.Delete([]byte(word))
	})
}

func GetBlacklist(chatID int64) ([]*BlacklistEntry, error) {
	db, err := GetDB()
	if err != nil {
		return nil, err
	}
	if err := ensureBucketsOnce("blacklist", db, ensureBlacklistBuckets); err != nil {
		return nil, err
	}

	var entries []*BlacklistEntry
	err = db.View(func(tx *mongostore.Tx) error {
		chatsBucket := tx.Bucket([]byte("blacklist"))
		if chatsBucket == nil {
			return nil
		}
		chatBucket := chatsBucket.Bucket([]byte(strconv.FormatInt(chatID, 10)))
		if chatBucket == nil {
			return nil
		}

		c := chatBucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var entry BlacklistEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				continue
			}
			entries = append(entries, &entry)
		}
		return nil
	})

	return entries, err
}

func IsBlacklisted(chatID int64, word string) bool {
	db, err := GetDB()
	if err != nil {
		return false
	}
	if err := ensureBucketsOnce("blacklist", db, ensureBlacklistBuckets); err != nil {
		return false
	}

	found := false
	db.View(func(tx *mongostore.Tx) error {
		chatsBucket := tx.Bucket([]byte("blacklist"))
		if chatsBucket == nil {
			return nil
		}
		chatBucket := chatsBucket.Bucket([]byte(strconv.FormatInt(chatID, 10)))
		if chatBucket == nil {
			return nil
		}

		if chatBucket.Get([]byte(word)) != nil {
			found = true
		}
		return nil
	})

	return found
}

func SetBlacklistSettings(chatID int64, settings *BlacklistSettings) error {
	db, err := GetDB()
	if err != nil {
		return err
	}
	if err := ensureBucketsOnce("blacklist", db, ensureBlacklistBuckets); err != nil {
		return err
	}

	return db.Update(func(tx *mongostore.Tx) error {
		settingsBucket, err := tx.CreateBucketIfNotExists([]byte("blacklist_settings"))
		if err != nil {
			return err
		}
		data, err := json.Marshal(settings)
		if err != nil {
			return err
		}

		return settingsBucket.Put([]byte(strconv.FormatInt(chatID, 10)), data)
	})
}

func GetBlacklistSettings(chatID int64) (*BlacklistSettings, error) {
	db, err := GetDB()
	if err != nil {
		return nil, err
	}
	if err := ensureBucketsOnce("blacklist", db, ensureBlacklistBuckets); err != nil {
		return nil, err
	}

	settings := &BlacklistSettings{Action: ActionDelete}
	err = db.View(func(tx *mongostore.Tx) error {
		settingsBucket := tx.Bucket([]byte("blacklist_settings"))
		if settingsBucket == nil {
			return nil
		}
		data := settingsBucket.Get([]byte(strconv.FormatInt(chatID, 10)))
		if data == nil {
			return nil
		}

		return json.Unmarshal(data, settings)
	})

	return settings, err
}

func GetBlacklistCount(chatID int64) (int, error) {
	db, err := GetDB()
	if err != nil {
		return 0, err
	}
	if err := ensureBucketsOnce("blacklist", db, ensureBlacklistBuckets); err != nil {
		return 0, err
	}

	count := 0
	err = db.View(func(tx *mongostore.Tx) error {
		chatsBucket := tx.Bucket([]byte("blacklist"))
		if chatsBucket == nil {
			return nil
		}
		chatBucket := chatsBucket.Bucket([]byte(strconv.FormatInt(chatID, 10)))
		if chatBucket == nil {
			return nil
		}

		c := chatBucket.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			count++
		}
		return nil
	})

	return count, err
}

func ClearBlacklist(chatID int64) error {
	db, err := GetDB()
	if err != nil {
		return err
	}
	if err := ensureBucketsOnce("blacklist", db, ensureBlacklistBuckets); err != nil {
		return err
	}

	return db.Update(func(tx *mongostore.Tx) error {
		chatsBucket := tx.Bucket([]byte("blacklist"))
		if chatsBucket == nil {
			return nil
		}
		key := []byte(strconv.FormatInt(chatID, 10))
		if chatsBucket.Bucket(key) == nil {
			return nil
		}
		return chatsBucket.DeleteBucket(key)
	})
}

func CloseBlacklistDB() error {
	return nil
}
