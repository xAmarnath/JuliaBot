package db

import (
	"encoding/json"
	"fmt"
	"main/internal/mongostore"
	"sort"
	"strconv"
	"time"
)

type TamilMVAlert struct {
	ID, ChatID, UserID    int64
	Title                 string
	Interval, LastChecked int64
	LastSeen              string
	Enabled               int64
	CreatedAt             int64
}

var alertsBucket = []byte("tamilmv_alerts")

func SaveTamilMVAlert(a *TamilMVAlert) error {
	d, e := GetDB()
	if e != nil {
		return e
	}
	return d.Update(func(tx *mongostore.Tx) error {
		b, e := tx.CreateBucketIfNotExists(alertsBucket)
		if e != nil {
			return e
		}
		if a.ID == 0 {
			n, e := b.NextSequence()
			if e != nil {
				return e
			}
			a.ID = int64(n)
			a.CreatedAt = time.Now().Unix()
			a.Enabled = 1
		} else {
			raw := b.Get([]byte(strconv.FormatInt(a.ID, 10)))
			if raw == nil {
				return fmt.Errorf("alert not found")
			}
			var old TamilMVAlert
			if e = json.Unmarshal(raw, &old); e != nil {
				return e
			}
			if old.UserID != a.UserID {
				return fmt.Errorf("alert not found")
			}
			old.Title = a.Title
			old.Interval = a.Interval
			*a = old
		}
		raw, e := json.Marshal(a)
		if e != nil {
			return e
		}
		return b.Put([]byte(strconv.FormatInt(a.ID, 10)), raw)
	})
}
func listAlerts(match func(TamilMVAlert) bool) ([]TamilMVAlert, error) {
	d, e := GetDB()
	if e != nil {
		return nil, e
	}
	var out []TamilMVAlert
	e = d.View(func(tx *mongostore.Tx) error {
		b := tx.Bucket(alertsBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var a TamilMVAlert
			if e := json.Unmarshal(v, &a); e != nil {
				return e
			}
			if match(a) {
				out = append(out, a)
			}
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, e
}
func ListTamilMVAlerts(uid int64) ([]TamilMVAlert, error) {
	return listAlerts(func(a TamilMVAlert) bool { return a.UserID == uid })
}
func DueTamilMVAlerts(now int64) ([]TamilMVAlert, error) {
	return listAlerts(func(a TamilMVAlert) bool {
		return a.Enabled == 1 && (a.LastChecked == 0 || a.LastChecked+a.Interval <= now)
	})
}
func updateAlert(id, uid int64, ownerCheck bool, fn func(*TamilMVAlert) bool) error {
	d, e := GetDB()
	if e != nil {
		return e
	}
	return d.Update(func(tx *mongostore.Tx) error {
		b := tx.Bucket(alertsBucket)
		if b == nil {
			return nil
		}
		key := []byte(strconv.FormatInt(id, 10))
		raw := b.Get(key)
		if raw == nil {
			return nil
		}
		var a TamilMVAlert
		if e := json.Unmarshal(raw, &a); e != nil {
			return e
		}
		if ownerCheck && a.UserID != uid {
			return nil
		}
		if !fn(&a) {
			return b.Delete(key)
		}
		raw, e := json.Marshal(a)
		if e != nil {
			return e
		}
		return b.Put(key, raw)
	})
}
func DeleteTamilMVAlert(id, uid int64) error {
	return updateAlert(id, uid, true, func(*TamilMVAlert) bool { return false })
}
func SetTamilMVAlertEnabled(id, uid int64, enabled bool) error {
	return updateAlert(id, uid, true, func(a *TamilMVAlert) bool {
		a.Enabled = 0
		if enabled {
			a.Enabled = 1
		}
		return true
	})
}
func SetTamilMVAlertInterval(id, uid, seconds int64) error {
	return updateAlert(id, uid, true, func(a *TamilMVAlert) bool { a.Interval = seconds; return true })
}
func TouchTamilMVAlert(id int64, seen string, checked int64) error {
	return updateAlert(id, 0, false, func(a *TamilMVAlert) bool { a.LastSeen = seen; a.LastChecked = checked; return true })
}
