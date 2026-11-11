package extras

import (
	"sync"
	"time"
)

// StartStatistics starts one writer for both counters. Call the returned stop
// function after stopping updates and before closing the database.
func StartStatistics() func() {
	return startStatisticsFlusher(30*time.Second, func() {
		chatStatsFlush()
		userPerfFlushAll()
	})
}

func startStatisticsFlusher(interval time.Duration, flush func()) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				flush()
			case <-stop:
				flush()
				return
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(stop) })
		<-done
	}
}
