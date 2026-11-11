package extras

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestStatisticsShutdownSavesBeforeReturning(t *testing.T) {
	var saved atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	stop := startStatisticsFlusher(time.Hour, func() {
		close(started)
		<-release
		saved.Add(1)
	})
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not flush pending statistics")
	}
	select {
	case <-done:
		t.Fatal("shutdown returned before the save finished")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish after the save")
	}
	stop()
	if saved.Load() != 1 {
		t.Fatal("repeated shutdown duplicated the final save")
	}
}
