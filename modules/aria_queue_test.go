package modules

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func waitQueued(t *testing.T, q *ariaQueue, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		q.mu.Lock()
		got := len(q.waiters)
		q.mu.Unlock()
		if got == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("queue did not reach expected length")
}

func TestAriaQueueFIFOAndCancellation(t *testing.T) {
	q := &ariaQueue{limit: 2}
	a, _ := q.acquire(context.Background())
	b, _ := q.acquire(context.Background())
	defer a()
	defer b()
	type admitted struct {
		id      int
		release func()
		err     error
	}
	got := make(chan admitted, 3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 3; i++ {
		c := context.Background()
		if i == 1 {
			c = ctx
		}
		go func(id int, c context.Context) { r, e := q.acquire(c); got <- admitted{id, r, e} }(i, c)
		waitQueued(t, q, i+1)
	}
	cancel()
	x := <-got
	if x.id != 1 || !errors.Is(x.err, context.Canceled) {
		t.Fatalf("cancel: %+v", x)
	}
	a()
	x = <-got
	if x.id != 0 || x.err != nil {
		t.Fatalf("first: %+v", x)
	}
	x.release()
	x = <-got
	if x.id != 2 || x.err != nil {
		t.Fatalf("second: %+v", x)
	}
	x.release()
	b()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.active != 0 || len(q.waiters) != 0 {
		t.Fatal("leaked slot")
	}
}

func TestAriaQueueConcurrentCancelAdmission(t *testing.T) {
	q := &ariaQueue{limit: 2}
	var wg sync.WaitGroup
	var active atomic.Int32
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go cancel()
			release, err := q.acquire(ctx)
			if err != nil {
				return
			}
			if active.Add(1) > 2 {
				t.Error("more than two downloads admitted")
			}
			active.Add(-1)
			release()
			release()
		}()
	}
	wg.Wait()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.active != 0 || len(q.waiters) != 0 {
		t.Fatalf("leaked slots: %d, waiters: %d", q.active, len(q.waiters))
	}
}
