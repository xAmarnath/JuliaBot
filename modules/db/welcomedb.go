package db

import (
	"encoding/json"
	"strconv"

	"main/internal/mongostore"
)

type WelcomeMessage struct {
	Content        string `json:"content"`
	MediaType      string `json:"media_type,omitempty"`
	FileID         string `json:"file_id,omitempty"`
	Buttons        string `json:"buttons,omitempty"`
	DeletePrevious bool   `json:"delete_previous"`
	AutoDeleteSec  int    `json:"auto_delete_sec"`
	Enabled        bool   `json:"enabled"`
}

func greetingKey(goodbye bool) []byte {
	if goodbye {
		return []byte("bye")
	}
	return []byte("msg")
}
func lastGreetingKey(goodbye bool) []byte {
	if goodbye {
		return []byte("last_bye_id")
	}
	return []byte("last_msg_id")
}
func welcomeChatBucket(tx *mongostore.Tx, chatID int64, create bool) (*mongostore.Bucket, error) {
	b := tx.Bucket([]byte("welcome"))
	if create {
		var err error
		b, err = tx.CreateBucketIfNotExists([]byte("welcome"))
		if err != nil {
			return nil, err
		}
		return b.CreateBucketIfNotExists([]byte(strconv.FormatInt(chatID, 10)))
	}
	if b == nil {
		return nil, nil
	}
	return b.Bucket([]byte(strconv.FormatInt(chatID, 10))), nil
}
func GetGreeting(chatID int64, goodbye bool) (*WelcomeMessage, error) {
	database, err := GetDB()
	if err != nil {
		return nil, err
	}
	var msg *WelcomeMessage
	err = database.View(func(tx *mongostore.Tx) error {
		b, err := welcomeChatBucket(tx, chatID, false)
		if err != nil || b == nil {
			return err
		}
		raw := b.Get(greetingKey(goodbye))
		if raw == nil {
			return nil
		}
		msg = &WelcomeMessage{}
		return json.Unmarshal(raw, msg)
	})
	return msg, err
}

// Read/modify/write in a single transaction so simultaneous admin settings survive.
func ModifyGreeting(chatID int64, goodbye bool, modify func(*WelcomeMessage)) error {
	database, err := GetDB()
	if err != nil {
		return err
	}
	return database.Update(func(tx *mongostore.Tx) error {
		b, err := welcomeChatBucket(tx, chatID, true)
		if err != nil {
			return err
		}
		cfg := &WelcomeMessage{}
		if raw := b.Get(greetingKey(goodbye)); raw != nil {
			if err := json.Unmarshal(raw, cfg); err != nil {
				return err
			}
		}
		modify(cfg)
		raw, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		return b.Put(greetingKey(goodbye), raw)
	})
}
func SetWelcome(chatID int64, msg *WelcomeMessage) error {
	return ModifyGreeting(chatID, false, func(cfg *WelcomeMessage) { *cfg = *msg })
}
func SetGoodbye(chatID int64, msg *WelcomeMessage) error {
	return ModifyGreeting(chatID, true, func(cfg *WelcomeMessage) { *cfg = *msg })
}
func GetWelcome(chatID int64) (*WelcomeMessage, error) { return GetGreeting(chatID, false) }
func GetGoodbye(chatID int64) (*WelcomeMessage, error) { return GetGreeting(chatID, true) }
func SetLastGreetingID(chatID int64, goodbye bool, msgID int) error {
	return SetLastGreetingIDs(chatID, goodbye, []int32{int32(msgID)})
}
func SetLastGreetingIDs(chatID int64, goodbye bool, ids []int32) error {
	database, err := GetDB()
	if err != nil {
		return err
	}
	return database.Update(func(tx *mongostore.Tx) error {
		b, err := welcomeChatBucket(tx, chatID, true)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(ids)
		if err != nil {
			return err
		}
		return b.Put(lastGreetingKey(goodbye), raw)
	})
}
func GetLastGreetingID(chatID int64, goodbye bool) (int, error) {
	ids, err := GetLastGreetingIDs(chatID, goodbye)
	if len(ids) == 0 {
		return 0, err
	}
	return int(ids[0]), err
}
func decodeGreetingIDs(raw []byte) ([]int32, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// Older deployments saved a single decimal message ID.
	if id, err := strconv.ParseInt(string(raw), 10, 32); err == nil {
		if id <= 0 {
			return nil, nil
		}
		return []int32{int32(id)}, nil
	}
	var ids []int32
	err := json.Unmarshal(raw, &ids)
	return ids, err
}
func GetLastGreetingIDs(chatID int64, goodbye bool) ([]int32, error) {
	database, err := GetDB()
	if err != nil {
		return nil, err
	}
	var ids []int32
	err = database.View(func(tx *mongostore.Tx) error {
		b, err := welcomeChatBucket(tx, chatID, false)
		if err != nil || b == nil {
			return err
		}
		ids, err = decodeGreetingIDs(b.Get(lastGreetingKey(goodbye)))
		return err
	})
	return ids, err
}
func SetLastWelcomeID(chatID int64, msgID int) error { return SetLastGreetingID(chatID, false, msgID) }
func GetLastWelcomeID(chatID int64) (int, error)     { return GetLastGreetingID(chatID, false) }
