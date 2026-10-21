package content

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestBoundedMemStoreEvictsOldestFirstPastTheCap(t *testing.T) {
	ctx := context.Background()
	var evictedBlobs int
	var evictedBytes int64
	m := NewBoundedMemStore(100, func(n int, b int64) { evictedBlobs += n; evictedBytes += b })
	blob := func(c byte) []byte { return bytes.Repeat([]byte{c}, 40) }
	a, _ := m.Put(ctx, blob('a'))
	b, _ := m.Put(ctx, blob('b'))
	if st := m.Stats(); st.Entries != 2 || st.Bytes != 80 {
		t.Fatalf("stats %+v", st)
	}
	c, _ := m.Put(ctx, blob('c')) // 120 > 100: the oldest (a) goes
	if _, err := m.Get(ctx, a.Digest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest blob must be evicted: %v", err)
	}
	for _, ad := range []Address{b, c} {
		if _, err := m.Get(ctx, ad.Digest); err != nil {
			t.Fatalf("newer blob must survive: %v", err)
		}
	}
	if st := m.Stats(); st.Entries != 2 || st.Bytes != 80 {
		t.Fatalf("stats after eviction %+v", st)
	}
	if evictedBlobs != 1 || evictedBytes != 40 {
		t.Fatalf("onEvict saw %d blobs %d bytes", evictedBlobs, evictedBytes)
	}
	// re-putting an identical blob is idempotent and does not double count
	m.Put(ctx, blob('c'))
	if st := m.Stats(); st.Entries != 2 || st.Bytes != 80 {
		t.Fatalf("idempotent put changed stats %+v", st)
	}
	// a blob larger than the whole cap is not retained and nothing stays over the cap
	m.Put(ctx, bytes.Repeat([]byte{'z'}, 500))
	if st := m.Stats(); st.Bytes > 100 || st.Entries != 0 {
		t.Fatalf("oversized blob must not be retained: %+v", st)
	}
}

func TestBoundedMemStoreNeverExceedsTheCapUnderChurn(t *testing.T) {
	ctx := context.Background()
	m := NewBoundedMemStore(1000, nil)
	for i := 0; i < 5000; i++ {
		m.Put(ctx, []byte{byte(i), byte(i >> 8), byte(i >> 16), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
		if st := m.Stats(); st.Bytes > 1000 {
			t.Fatalf("over cap at %d: %+v", i, st)
		}
	}
	if st := m.Stats(); st.Entries == 0 || len(m.blobs) != st.Entries {
		t.Fatalf("bookkeeping drift %+v blobs=%d", st, len(m.blobs))
	}
}

func TestUnboundedMemStoreStillKeepsEverything(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	for i := 0; i < 50; i++ {
		m.Put(ctx, bytes.Repeat([]byte{byte(i)}, 1000))
	}
	if st := m.Stats(); st.Entries != 50 || st.Bytes != 50000 {
		t.Fatalf("%+v", st)
	}
}
