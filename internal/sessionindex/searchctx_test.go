package sessionindex

import (
	"context"
	"testing"
)

func TestSearchContextCancelled(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 20; i++ {
		writeSession(t, e.projects, "-p", sid(i), session("/p", "cancelword"))
	}
	ix, _ := e.update(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if hits, err := ix.SearchContext(ctx, "cancelword", 50); err == nil || len(hits) != 0 {
		t.Fatalf("cancelled: %v %d hits", err, len(hits))
	}
	if hits, err := ix.SearchContext(context.Background(), "cancelword", 50); err != nil || len(hits) != 20 {
		t.Fatalf("live: %v %d hits", err, len(hits))
	}
}
