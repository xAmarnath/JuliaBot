package mongostore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

func memoryStore() *DB {
	return &DB{records: map[string]Record{}, children: map[string]map[string]struct{}{},
		commit: func(context.Context, []mongo.WriteModel) (bool, error) { return false, nil }}
}

func putCache(d *DB, value []byte) error {
	return d.Update(func(tx *Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("root"))
		if err != nil {
			return err
		}
		return b.Put([]byte("key"), value)
	})
}

func readCache(t *testing.T, d *DB, want string) {
	t.Helper()
	if err := d.View(func(tx *Tx) error {
		if got := string(tx.Bucket([]byte("root")).Get([]byte("key"))); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCacheCommitIsolation(t *testing.T) {
	d := memoryStore()
	value := []byte("old")
	if err := putCache(d, value); err != nil {
		t.Fatal(err)
	}
	value[0] = 'X'
	readCache(t, d, "old")
	started, release := make(chan struct{}), make(chan struct{})
	d.commit = func(context.Context, []mongo.WriteModel) (bool, error) { close(started); <-release; return false, nil }
	done := make(chan error, 1)
	go func() { done <- putCache(d, []byte("new")) }()
	<-started
	viewed := make(chan struct{})
	go func() { defer close(viewed); readCache(t, d, "old") }()
	select {
	case <-viewed:
	case <-time.After(2 * time.Second):
		close(release)
		<-done
		t.Fatal("network commit blocked cached reads")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	readCache(t, d, "new")
	if err := d.View(func(tx *Tx) error {
		b := tx.Bucket([]byte("root"))
		b.Get([]byte("key"))[0] = 'X'
		key, val := b.Cursor().First()
		key[0] = 'Y'
		val[0] = 'Z'
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	readCache(t, d, "new")
}

func TestCacheRollbackAndUnknownCommit(t *testing.T) {
	d := memoryStore()
	if err := putCache(d, []byte("old")); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("write failed")
	err := d.Update(func(tx *Tx) error { _ = tx.Bucket([]byte("root")).Put([]byte("key"), []byte("bad")); return failure })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	readCache(t, d, "old")
	d.commit = func(context.Context, []mongo.WriteModel) (bool, error) { return false, failure }
	if err := putCache(d, []byte("bad")); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	readCache(t, d, "old")
	d.commit = func(context.Context, []mongo.WriteModel) (bool, error) { return true, failure }
	if err := putCache(d, []byte("uncertain")); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	called := false
	for _, run := range []func(func(*Tx) error) error{d.View, d.Update} {
		if err := run(func(*Tx) error { called = true; return nil }); !errors.Is(err, failure) {
			t.Fatalf("uncertain cache served: %v", err)
		}
	}
	if called {
		t.Fatal("callback ran with uncertain cache")
	}
}

func TestCacheSequencesAndSubtreeReplacement(t *testing.T) {
	d := memoryStore()
	if err := putCache(d, []byte("old")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			if err := d.Update(func(tx *Tx) error { _, err := tx.Bucket([]byte("root")).NextSequence(); return err }); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if err := d.View(func(tx *Tx) error {
		if n := tx.Bucket([]byte("root")).Sequence(); n != 40 {
			t.Errorf("lost increment: %d", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for range 30 {
		if err := d.Update(func(tx *Tx) error {
			if err := tx.DeleteBucket([]byte("root")); err != nil {
				return err
			}
			b, err := tx.CreateBucketIfNotExists([]byte("root"))
			if err != nil {
				return err
			}
			child, err := b.CreateBucketIfNotExists([]byte("nested"))
			if err != nil {
				return err
			}
			if err = child.Put([]byte("b"), []byte("two")); err != nil {
				return err
			}
			return child.Put([]byte("a"), []byte{})
		}); err != nil {
			t.Fatal(err)
		}
		if err := d.View(func(tx *Tx) error {
			b := tx.Bucket([]byte("root"))
			if b.Get([]byte("key")) != nil || b.Stats().KeyN != 1 {
				t.Error("subtree replacement")
			}
			child := b.Bucket([]byte("nested"))
			if child.Stats().KeyN != 2 {
				t.Error("child index missing")
			}
			c := child.Cursor()
			k, v := c.First()
			if string(k) != "a" || v == nil {
				t.Error("empty/sort")
			}
			k, v = c.Next()
			if string(k) != "b" || string(v) != "two" {
				t.Error("cursor")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
