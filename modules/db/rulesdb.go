package db

import (
	"encoding/json"
	"strconv"

	"main/internal/mongostore"
)

type Rules struct {
	Content   string `json:"content"`
	MediaType string `json:"media_type,omitempty"`
	FileID    string `json:"file_id,omitempty"`
	Buttons   string `json:"buttons,omitempty"`
}

func ensureRulesBuckets(db *mongostore.DB) error {
	return db.Update(func(tx *mongostore.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("rules"))
		return err
	})
}

func SetRulesWithMedia(chatID int64, rules *Rules) error {
	db, err := GetDB()
	if err != nil {
		return err
	}
	if err := ensureBucketsOnce("rules", db, ensureRulesBuckets); err != nil {
		return err
	}

	return db.Update(func(tx *mongostore.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("rules"))
		if err != nil {
			return err
		}
		data, err := json.Marshal(rules)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(strconv.FormatInt(chatID, 10)), data)
	})
}

func SetRules(chatID int64, rulesText string) error {
	return SetRulesWithMedia(chatID, &Rules{Content: rulesText})
}

func GetRulesWithMedia(chatID int64) (*Rules, error) {
	db, err := GetDB()
	if err != nil {
		return nil, err
	}
	if err := ensureBucketsOnce("rules", db, ensureRulesBuckets); err != nil {
		return nil, err
	}

	var rules *Rules
	err = db.View(func(tx *mongostore.Tx) error {
		bucket := tx.Bucket([]byte("rules"))
		if bucket == nil {
			return nil
		}
		data := bucket.Get([]byte(strconv.FormatInt(chatID, 10)))
		if data == nil {
			return nil
		}

		rules = &Rules{}
		if err := json.Unmarshal(data, rules); err != nil {
			rules = &Rules{Content: string(data)}
		}
		return nil
	})

	return rules, err
}

func GetRules(chatID int64) (string, error) {
	rules, err := GetRulesWithMedia(chatID)
	if err != nil {
		return "", err
	}
	if rules == nil {
		return "", nil
	}
	return rules.Content, nil
}

func DeleteRules(chatID int64) error {
	db, err := GetDB()
	if err != nil {
		return err
	}
	if err := ensureBucketsOnce("rules", db, ensureRulesBuckets); err != nil {
		return err
	}

	return db.Update(func(tx *mongostore.Tx) error {
		bucket := tx.Bucket([]byte("rules"))
		if bucket == nil {
			return nil
		}
		return bucket.Delete([]byte(strconv.FormatInt(chatID, 10)))
	})
}

func HasRules(chatID int64) bool {
	rules, err := GetRulesWithMedia(chatID)
	return err == nil && rules != nil && (rules.Content != "" || rules.FileID != "")
}

func CloseRulesDB() error {
	return nil
}
