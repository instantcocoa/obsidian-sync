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
