package kisskh

import (
	"context"
	"errors"
	"sync"
)

// Subtitle-bearing episodes are published. Zero-subtitle entries may be countdown placeholders;
// check the video API rather than equating a listed ID with a release.
func (c *Client) CheckReleases(ctx context.Context, d *Drama) error {
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				ep := &d.Episodes[i]
				if ep.Sub > 0 {
					ep.Released = true
					continue
				}
				_, err := c.video(ctx, ep.ID)
				ep.Released = err == nil
				if err != nil && !errors.Is(err, ErrNotReleased) {
					mu.Lock()
					if first == nil {
						first = err
					}
					mu.Unlock()
				}
			}
		}()
	}
	for i := range d.Episodes {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return first
}
