// obsync is the sync server for the obsync Obsidian plugin.
//
//	obsync serve  --data DIR [--listen :8080] [--admin-token T] [--acme-domain example.com]
//	obsync vault create --data DIR
//	obsync vault list   --data DIR
//	obsync gc           --data DIR [--retention 2160h]
//
// Invites are minted by a device (or with the admin token over HTTP), because
// the inviter must wrap the vault keys, which the server never holds.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"obsync/internal/api"
	"obsync/internal/blobstore"
	"obsync/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "vault":
		err = vault(os.Args[2:])
	case "gc":
		err = gc(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(`
usage:
  obsync serve        --data DIR [--listen :8080] [--admin-token T] [--acme-domain D] [--max-blob-mb N] [--retention 2160h]
  obsync vault create --data DIR
  obsync vault list   --data DIR
  obsync vault auth   --data DIR VAULT_ID va_TOKEN   (migrate a pre-authority vault)
  obsync gc           --data DIR [--retention 2160h]`))
}

func openStore(data string) (*store.Store, *blobstore.FS, error) {
	if data == "" {
		return nil, nil, errors.New("--data is required")
	}
	if err := os.MkdirAll(data, 0o750); err != nil {
		return nil, nil, err
	}
	st, err := store.Open(filepath.Join(data, "obsync.db"))
	if err != nil {
		return nil, nil, err
	}
	bs, err := blobstore.New(filepath.Join(data, "blobs"))
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return st, bs, nil
}

// adminToken returns the configured token, or creates and persists one in
// DIR/admin-token on first run (printed once).
func adminToken(data, flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if env := os.Getenv("OBSYNC_ADMIN_TOKEN"); env != "" {
		return env, nil
	}
	p := filepath.Join(data, "admin-token")
	if b, err := os.ReadFile(p); err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	tok, _ := store.NewToken("ad_")
	if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "generated admin token (saved to %s):\n  %s\n", p, tok)
	return tok, nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	data := fs.String("data", "", "data directory")
	listen := fs.String("listen", ":8080", "listen address (ignored with --acme-domain, which uses :443 and :80)")
	admin := fs.String("admin-token", "", "admin bearer token (default: $OBSYNC_ADMIN_TOKEN or DIR/admin-token)")
	acme := fs.String("acme-domain", "", "obtain a Let's Encrypt certificate for this domain and serve HTTPS")
	maxBlob := fs.Int64("max-blob-mb", 1024, "maximum blob size in MiB")
	retention := fs.Duration("retention", 90*24*time.Hour, "keep superseded blobs for this long before GC")
	gcEvery := fs.Duration("gc-interval", 24*time.Hour, "how often to run GC (0 disables)")
	trustProxy := fs.Bool("trust-proxy", false, "use X-Forwarded-For for rate limiting (only behind a proxy you control)")
	authRate := fs.Int("auth-rate", 10, "max unauthenticated/failed-auth requests per minute per IP (burst 2x)")
	fs.Parse(args)

	st, bs, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	tok, err := adminToken(*data, *admin)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv := api.New(api.Config{AdminToken: tok, MaxBlobSize: *maxBlob << 20, Logger: log, TrustProxy: *trustProxy, AuthRatePerMinute: *authRate, AuthBurst: *authRate * 2}, st, bs)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *gcEvery > 0 {
		go func() {
			t := time.NewTicker(*gcEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					n, err := srv.GC(ctx, *retention)
					log.Info("gc", "removed", n, "err", err)
				}
			}
		}()
	}

	h := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	if *acme != "" {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*acme),
			Cache:      autocert.DirCache(filepath.Join(*data, "acme")),
		}
		h.Addr = ":443"
		h.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate, MinVersion: tls.VersionTLS12}
		go func() { errc <- http.ListenAndServe(":80", m.HTTPHandler(nil)) }()
		go func() { errc <- h.ListenAndServeTLS("", "") }()
		log.Info("serving", "https", *acme, "data", *data)
	} else {
		h.Addr = *listen
		go func() { errc <- h.ListenAndServe() }()
		log.Info("serving", "addr", *listen, "data", *data)
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return h.Shutdown(sctx)
	}
}

func vault(args []string) error {
	if len(args) < 1 {
		return errors.New("vault create|list|auth")
	}
	fs := flag.NewFlagSet("vault", flag.ExitOnError)
	data := fs.String("data", "", "data directory")
	fs.Parse(args[1:])
	st, _, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	switch args[0] {
	case "create":
		v, err := st.CreateVault(context.Background())
		if err != nil {
			return err
		}
		fmt.Println(v.ID)
	case "list":
		vs, err := st.ListVaults(context.Background())
		if err != nil {
			return err
		}
		for _, v := range vs {
			fmt.Printf("%s\tepoch=%d\tseq=%d\tcreated=%s\n", v.ID, v.Epoch, v.Seq, time.UnixMilli(v.CreatedAt).Format(time.RFC3339))
		}
	case "auth":
		// obsync vault auth --data DIR VAULT_ID va_TOKEN
		// Installs the vault authority token for a vault created before the
		// server required one (DESIGN.md §5.8). The token is shown under
		// Settings → obsync → Advanced on any device that holds the keys.
		rest := fs.Args()
		if len(rest) != 2 {
			return errors.New("vault auth --data DIR VAULT_ID va_TOKEN")
		}
		if err := st.SetVaultAuth(context.Background(), rest[0], rest[1]); err != nil {
			return err
		}
		fmt.Println("vault authority set")
	default:
		return errors.New("vault create|list|auth")
	}
	return nil
}

func gc(args []string) error {
	fs := flag.NewFlagSet("gc", flag.ExitOnError)
	data := fs.String("data", "", "data directory")
	retention := fs.Duration("retention", 90*24*time.Hour, "keep superseded blobs for this long")
	fs.Parse(args)
	st, bs, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	srv := api.New(api.Config{AdminToken: "unused"}, st, bs)
	n, err := srv.GC(context.Background(), *retention)
	if err != nil {
		return err
	}
	fmt.Printf("removed %d blobs\n", n)
	return nil
}
