package api_test

// Regression tests from the fifth review (2026-11-07), which checked the
// fourth round's own server changes: a blob transfer that keeps moving is
// never cut by the request deadline, and the event log holds no secret and
// writes one line per event.
//
//   go test ./internal/api/ -run Zz -count=1

import (
	"bytes"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"obsync/internal/api"
	"obsync/internal/blobstore"
	"obsync/internal/store"
)

// main.go sets ReadTimeout/WriteTimeout 15 min on the whole server;
// the blob routes do nothing to extend them while bytes flow. The deadline
// is absolute from the start of the request, so a transfer that progresses
// steadily but takes longer than the deadline is cut, retried by the engine
// on the next cycle, cut again, and every other dirty file waits behind it
// (push uploads all missing blobs in one batch and aborts on the first
// error). With the default --max-blob-mb 1024 that is any blob above
// 15 min x link rate: ~110 MB on a 1 Mbit/s uplink. Stand-in here: a
// 500 ms ReadTimeout and an upload that never stalls for more than 100 ms.
func TestZzBlobUploadProgressDoesNotExtendTheDeadline(t *testing.T) {
	e := newEnv(t)
	vault, a, _ := e.setup()
	hs := &http.Server{Handler: e.srv, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 500 * time.Millisecond}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })

	pr, pw := io.Pipe()
	go func() {
		pw.Write(blob(1, "")[:33]) // header: version, epoch, salt, nonce
		for i := range 15 {
			time.Sleep(100 * time.Millisecond)
			pw.Write(bytes.Repeat([]byte{byte(i)}, 1024))
		}
		pw.Close()
	}()
	id := hexID("slow-upload")
	req, _ := http.NewRequest("PUT", "http://"+ln.Addr().String()+"/v1/vaults/"+vault+"/blobs/"+id, pr)
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("X-Obsync-Vault-Auth", authTok[vault])
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("a 1.5 s upload that never paused for more than 100 ms was cut by a 500 ms ReadTimeout (%v): the blob routes inherit the server-wide absolute deadline, so with main.go's 15 min any blob slower than max-blob/15 min never syncs", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("slow but steady upload rejected with %d: %s", res.StatusCode, b)
	}
}

// Holds (confirmation of aca5ce1/d383b06/8ca0627). The event log carries no
// bearer, invite or recovery token, an unauthenticated caller is "-", and a
// path value with a newline cannot start a second line.
func TestZzEventLogHoldsNoSecretsAndOneLinePerEvent(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir + "/db.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bs, _ := blobstore.New(dir + "/blobs")
	var log bytes.Buffer
	srv := api.New(api.Config{AdminToken: adminTok, Logger: slog.New(slog.NewTextHandler(&log, nil)), AuthRatePerMinute: -1}, st, bs)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	e := &env{t: t, ts: ts, srv: srv, st: st}

	var v store.Vault
	e.do("POST", "/v1/vaults", adminTok, nil, nil).expect(t, 201).json(t, &v)
	devTok := "dv_" + hex.EncodeToString(randBytes(32))
	invTok := "in_" + hex.EncodeToString(randBytes(32))
	rcTok := "rc_" + hex.EncodeToString(randBytes(32))
	e.do("GET", "/v1/vaults/"+v.ID, devTok, nil, nil).expect(t, 401)                                                       // auth.failed
	e.do("POST", "/v1/invites/"+invTok, "", map[string]any{"pub_kex": testPubKex()}, nil).expect(t, 401)                   // invite.redeem.failed
	e.do("POST", "/v1/vaults/evil%0Ainjected=1%20x/recovery/join", rcTok, map[string]any{"pub_kex": testPubKex()}, nil)    // recovery.join.failed, vault id with a newline
	e.do("POST", "/v1/vaults/"+v.ID+"/invites", adminTok, map[string]any{"keybox_enc": randBytes(64)}, nil).expect(t, 201) // invite.created by admin

	out := log.String()
	for _, secret := range []string{devTok, invTok, rcTok, adminTok} {
		if strings.Contains(out, secret) {
			t.Errorf("event log contains a credential (%s…):\n%s", secret[:6], out)
		}
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	events := strings.Count(out, "event=")
	if len(lines) != events {
		t.Errorf("%d lines for %d events: a path value broke a line\n%s", len(lines), events, out)
	}
	if !strings.Contains(out, "event=auth.failed") || !strings.Contains(out, "by=- ") {
		t.Errorf("expected an auth.failed event attributed to \"-\":\n%s", out)
	}
	if !strings.Contains(out, "event=invite.created") || !strings.Contains(out, "by=admin") {
		t.Errorf("expected an invite.created event attributed to admin:\n%s", out)
	}
	if !strings.Contains(out, `vault="evil\ninjected=1 x"`) {
		t.Errorf("expected the newline in the vault path value to be escaped:\n%s", out)
	}
}
