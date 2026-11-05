package sessionsapi

import "testing"

// A refresh that finds nothing new publishes nothing: the page reloads only
// on real changes.
func TestQuietRefreshPublishesNothing(t *testing.T) {
	_, _, p := newFixture(t)
	c := New(Options{Paths: p})
	c.Refresh(true)
	ch, cancel := c.Subscribe()
	defer cancel()
	for i := 0; i < 3; i++ {
		c.Refresh(true)
		c.Refresh(false)
	}
	select {
	case ev := <-ch:
		t.Fatalf("event on a quiet refresh: %s %s", ev.Name, ev.Data)
	default:
	}
}
