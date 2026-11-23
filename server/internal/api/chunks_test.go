package api_test

import (
	"context"
	"strings"
	"testing"

	"obsync/internal/store"
)

// Chunked versions (1.0): an op may list the blobs that hold its content.
// The server refuses a list whose blobs are not all uploaded, returns the
// list in order, keeps the chunks of live versions through a sweep with no
// retention, and lets them go once nothing refers to them.
func TestChunkedOpsLivenessAndValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v, a, _ := e.setup()
	id := func(c string) string { return strings.Repeat(c, 64) }
	whole := id("f")
	chunked := func(path string, base int64, chunks ...string) opIn {
		o := put(path, &whole, base)
		o.Chunks = chunks
		return o
	}
	e.upload(v, a, id("a"), blob(1, "chunk a")).expect(t, 201)
	// One chunk missing: refused, as for a missing blob.
	if r := e.ops(v, a, chunked("big", 0, id("a"), id("b"))).Results[0]; r.Error != "blob not uploaded" {
		t.Fatalf("missing chunk accepted: %+v", r)
	}
	e.upload(v, a, id("b"), blob(1, "chunk b")).expect(t, 201)
	r := e.ops(v, a, chunked("big", 0, id("a"), id("b"), id("a"))).Results[0]
	if r.Seq == 0 {
		t.Fatalf("chunked op refused: %+v", r)
	}
	f := e.changes(v, a, 0, "")
	if len(f.Ops) != 1 || len(f.Ops[0].Chunks) != 3 || f.Ops[0].Chunks[1] != id("b") || f.Ops[0].Chunks[2] != id("a") {
		t.Fatalf("chunks not returned in order: %+v", f.Ops)
	}
	// Bad shapes.
	del := put("other", nil, 0)
	del.Chunks = []string{id("a")}
	if r := e.ops(v, a, del).Results[0]; !strings.Contains(r.Error, "deletion") {
		t.Fatalf("deletion with chunks: %+v", r)
	}
	if r := e.ops(v, a, chunked("other", 0, "zz")).Results[0]; !strings.Contains(r.Error, "chunk ids") {
		t.Fatalf("bad chunk id: %+v", r)
	}
	many := make([]string, store.MaxChunks+1)
	for i := range many {
		many[i] = id("a")
	}
	if r := e.ops(v, a, chunked("other", 0, many...)).Results[0]; !strings.Contains(r.Error, "chunks") {
		t.Fatalf("too many chunks: %+v", r)
	}
	// Live chunks survive a sweep with no retention.
	const forever = int64(1) << 62
	if dead, err := e.st.DeadBlobs(ctx, v, forever); err != nil || len(dead) != 0 {
		t.Fatalf("live chunks listed dead: %v %v", dead, err)
	}
	if ok, _ := e.st.DeleteDeadBlob(ctx, v, id("a"), forever); ok {
		t.Fatal("a live chunk was deleted")
	}
	// Replace the head with an unchunked version: nothing keeps a and b.
	e.upload(v, a, id("c"), blob(1, "small")).expect(t, 201)
	c := id("c")
	if r2 := e.ops(v, a, put("big", &c, r.Seq)).Results[0]; r2.Seq == 0 {
		t.Fatalf("%+v", r2)
	}
	if dead, _ := e.st.DeadBlobs(ctx, v, forever); len(dead) != 2 {
		t.Fatalf("superseded chunks not dead: %v", dead)
	}
}

// A page of the feed, the snapshot or a history carries at most
// maxPageChunkIDs chunk ids, however many ops would fit by count; the
// client pages through the rest (review 14, F3).
func TestChunkListsDoNotInflatePages(t *testing.T) {
	e := newEnv(t)
	v, a, _ := e.setup()
	c := strings.Repeat("c", 64)
	e.upload(v, a, c, blob(1, "one chunk")).expect(t, 201)
	whole := strings.Repeat("f", 64)
	list := make([]string, store.MaxChunks)
	for i := range list {
		list[i] = c
	}
	for i := 0; i < 12; i++ {
		o := put("p"+strings.Repeat("x", i), &whole, 0)
		o.Chunks = list
		if r := e.ops(v, a, o).Results[0]; r.Seq == 0 {
			t.Fatalf("%+v", r)
		}
	}
	ids := func(ops []store.Op) (n int) {
		for _, o := range ops {
			n += len(o.Chunks)
		}
		return n
	}
	f := e.changes(v, a, 0, "")
	if !f.More || len(f.Ops) != 8 || ids(f.Ops) > 32768 {
		t.Fatalf("first page: more=%v ops=%d ids=%d", f.More, len(f.Ops), ids(f.Ops))
	}
	g := e.changes(v, a, f.Cursor, "")
	if g.More || len(g.Ops) != 4 {
		t.Fatalf("second page: more=%v ops=%d", g.More, len(g.Ops))
	}
	var snap feed
	e.do("GET", "/v1/vaults/"+v+"/snapshot", a.token, nil, nil).expect(t, 200).json(t, &snap)
	if !snap.More || ids(snap.Ops) > 32768 {
		t.Fatalf("snapshot page: more=%v ids=%d", snap.More, ids(snap.Ops))
	}
}
