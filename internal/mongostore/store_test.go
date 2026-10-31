package mongostore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func TestMongoTransactions(t *testing.T) {
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		t.Skip("MONGODB_TEST_URI not set")
	}
	d, err := Open(uri, "Main_Database", fmt.Sprintf("test_store_%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.collection.Drop(ctx); err != nil {
			t.Error(err)
		}
	}()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(d.Update(func(tx *Tx) error {
		b, e := tx.CreateBucketIfNotExists([]byte("root"))
		if e != nil {
			return e
		}
		child, e := b.CreateBucketIfNotExists([]byte{0, 255, '/'})
		if e != nil {
			return e
		}
		if e = child.Put([]byte("b"), []byte("two")); e != nil {
			return e
		}
		if e = child.Put([]byte("a"), []byte{}); e != nil {
			return e
		}
		return child.SetSequence(41)
	}))
	must(d.View(func(tx *Tx) error {
		b := tx.Bucket([]byte("root")).Bucket([]byte{0, 255, '/'})
		if b.Get([]byte("missing")) != nil || b.Get([]byte("a")) == nil {
			t.Error("missing and empty values confused")
		}
		if b.Sequence() != 41 || b.Stats().KeyN != 2 {
			t.Error("sequence/count mismatch")
		}
		c := b.Cursor()
		k, _ := c.First()
		if string(k) != "a" {
			t.Error("first")
		}
		k, v := c.Seek([]byte("b"))
		if string(k) != "b" || string(v) != "two" {
			t.Error("seek")
		}
		k, _ = c.Last()
		if string(k) != "b" {
			t.Error("last")
		}
		k, _ = c.Prev()
		if string(k) != "a" {
			t.Error("prev")
		}
		if !errors.Is(b.Put([]byte("x"), nil), ErrReadOnly) {
			t.Error("read-only write accepted")
		}
		return nil
	}))
	rollback := errors.New("rollback")
	err = d.Update(func(tx *Tx) error {
		b := tx.Bucket([]byte("root"))
		if e := b.Put([]byte("rollback"), []byte("bad")); e != nil {
			return e
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	must(d.View(func(tx *Tx) error {
		if tx.Bucket([]byte("root")).Get([]byte("rollback")) != nil {
			t.Error("rollback persisted")
		}
		return nil
	}))
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			errs <- d.Update(func(tx *Tx) error {
				_, e := tx.Bucket([]byte("root")).Bucket([]byte{0, 255, '/'}).NextSequence()
				return e
			})
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		must(e)
	}
	must(d.View(func(tx *Tx) error {
		if tx.Bucket([]byte("root")).Bucket([]byte{0, 255, '/'}).Sequence() != 49 {
			t.Error("lost concurrent increment")
		}
		return nil
	}))
	must(d.Update(func(tx *Tx) error { return tx.Bucket([]byte("root")).DeleteBucket([]byte{0, 255, '/'}) }))
	must(d.View(func(tx *Tx) error {
		b := tx.Bucket([]byte("root"))
		if b.Bucket([]byte{0, 255, '/'}) != nil || b.Stats().KeyN != 0 {
			t.Error("subtree not deleted")
		}
		return nil
	}))
}

func TestPaths(t *testing.T) {
	if Path(Path("", []byte("a")), []byte("b")) == Path("", []byte("a/b")) {
		t.Fatal("path collision")
	}
	c := &Cursor{records: []Record{{Key: []byte{0}, Value: []byte("zero")}, {Key: []byte{255}, Bucket: true}}, index: -1}
	k, v := c.Seek([]byte{1})
	if !bytes.Equal(k, []byte{255}) || v != nil {
		t.Fatal("binary seek or nested bucket mismatch")
	}
	if k, _ := c.Next(); k != nil {
		t.Fatal("end of cursor")
	}
}
