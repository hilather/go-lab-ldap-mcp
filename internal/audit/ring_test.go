package audit

import (
	"testing"
	"time"
)

func TestRingIsBounded(t *testing.T) {
	t.Parallel()
	r := NewRing(3)
	for i := 0; i < 10; i++ {
		r.Emit(t.Context(), Event{Action: ActionUserCreate, Actor: "token:admin", Result: ResultSuccess})
	}
	if r.Len() != 3 {
		t.Fatalf("len = %d", r.Len())
	}
	page, err := r.List(t.Context(), ListQuery{PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 3 {
		t.Fatalf("items = %d", len(page.Items))
	}
	// Newest first; last emitted has the highest seq.
	if page.Items[0].Seq < page.Items[2].Seq {
		t.Fatalf("not newest-first: %+v", page.Items)
	}
}

func TestRingExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := NewRing(8)
	r.SetTTL(time.Hour)
	r.SetClock(func() time.Time { return now })
	r.Emit(t.Context(), Event{Action: ActionAuthenticate, Actor: "token:old", Result: ResultSuccess})
	now = now.Add(2 * time.Hour)
	r.Emit(t.Context(), Event{Action: ActionAuthenticate, Actor: "token:new", Result: ResultSuccess})
	page, err := r.List(t.Context(), ListQuery{PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Actor != "token:new" {
		t.Fatalf("%+v", page.Items)
	}
}

func TestRingFilterAndCursor(t *testing.T) {
	t.Parallel()
	r := NewRing(32)
	r.Emit(t.Context(), Event{Action: ActionUserCreate, Actor: "token:admin", Target: "a", Result: ResultSuccess})
	r.Emit(t.Context(), Event{Action: ActionUserDelete, Actor: "token:admin", Target: "a", Result: ResultSuccess})
	r.Emit(t.Context(), Event{Action: ActionUserCreate, Actor: "session:s1", Target: "b", Result: ResultSuccess})

	page, err := r.List(t.Context(), ListQuery{Action: ActionUserCreate, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Target != "b" || !page.HasMore {
		t.Fatalf("%+v", page)
	}
	next, err := r.List(t.Context(), ListQuery{Action: ActionUserCreate, PageSize: 1, AfterSeq: page.NextSeq})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Items) != 1 || next.Items[0].Target != "a" || next.HasMore {
		t.Fatalf("%+v", next)
	}

	byActor, err := r.List(t.Context(), ListQuery{Actor: "session:s1", PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(byActor.Items) != 1 || byActor.Items[0].Target != "b" {
		t.Fatalf("%+v", byActor.Items)
	}
}
