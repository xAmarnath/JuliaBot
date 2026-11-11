package modules

import (
	"context"
	"errors"
	"sync"
)

// Requests reserve a slot in arrival order. A cancelled waiter is removed before
// it can launch a process; a cancellation racing with admission returns its slot.
type ariaQueue struct {
	mu      sync.Mutex
	active  int
	limit   int
	waiters []chan struct{}
}

var ariaDownloads = ariaQueue{limit: 2}

func (q *ariaQueue) acquire(ctx context.Context) (func(), error) {
	q.mu.Lock()
	if err := ctx.Err(); err != nil {
		q.mu.Unlock()
		return nil, err
	}
	if len(q.waiters) >= 64 {
		q.mu.Unlock()
		return nil, errors.New("download queue is full; try again later")
	}
	ready := make(chan struct{})
	q.waiters = append(q.waiters, ready)
	q.admitLocked()
	q.mu.Unlock()
	select {
	case <-ready:
		if err := ctx.Err(); err != nil {
			q.release()
			return nil, err
		}
		var once sync.Once
		return func() { once.Do(q.release) }, nil
	case <-ctx.Done():
		q.mu.Lock()
		for i, waiter := range q.waiters {
			if waiter == ready {
				q.waiters = append(q.waiters[:i], q.waiters[i+1:]...)
				q.mu.Unlock()
				return nil, ctx.Err()
			}
		}
		// Already admitted: its slot must be returned even when select chose cancellation.
		q.active--
		q.admitLocked()
		q.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (q *ariaQueue) admitLocked() {
	for q.active < q.limit && len(q.waiters) > 0 {
		ready := q.waiters[0]
		q.waiters[0] = nil
		q.waiters = q.waiters[1:]
		q.active++
		close(ready)
	}
}

func (q *ariaQueue) release() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.active--
	q.admitLocked()
}
