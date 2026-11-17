// obsync is the sync server for the obsync Obsidian plugin.
//
//	obsync serve  --data DIR --public-url https://sync.example.com [--listen 127.0.0.1:8080 | --acme-domain sync.example.com]
//	obsync vault create --data DIR          one-time create link (+ QR) for a new vault's first device
//	obsync vault list   --data DIR
//	obsync admin register --data DIR        one-time link that opens /admin in a browser to register a security key
//	obsync admin keys|remove|forget --data DIR
//	obsync gc           --data DIR [--retention 2160h]
//
// There is no admin token. Creating a vault takes a create link, minted here
// on the host or on the /admin page after a security-key sign-in; joining an
// existing vault takes an invite minted by a member device, because the
// inviter must wrap the vault keys, which the server never holds.
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
	"obsync/internal/qr"
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
	case "admin":
		err = adminCmd(os.Args[2:])
	case "gc":
		err = gc(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	runAtExit()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(`
usage:
  obsync serve          --data DIR --public-url https://host [--listen 127.0.0.1:8080 | --acme-domain host] [--trust-proxy CIDR] [--max-blob-mb N] [--retention 2160h]
  obsync vault create   --data DIR [--url https://host] [--ttl 1h]   print a one-time create link and its QR code
  obsync vault list     --data DIR
  obsync vault auth     --data DIR VAULT_ID va_TOKEN                 (migrate a pre-authority vault)
  obsync admin register --data DIR [--url https://host] [--ttl 1h]   print a one-time link that opens /admin in a browser, to register a security key or sign in
  obsync admin keys     --data DIR
  obsync admin remove   --data DIR NAME
  obsync admin forget   --data DIR          every browser needs a fresh register link to see /admin again
  obsync gc             --data DIR [--retention 2160h]

Run the vault and admin commands on the server host, as root (sudo) or as
the service user: they write to the database directly.`))
}

// atExit runs after the subcommand returns (main calls runAtExit).
var atExit []func()

func runAtExit() {
	for i := len(atExit) - 1; i >= 0; i-- {
		atExit[i]()
	}
}

func openStore(data string) (*store.Store, *blobstore.FS, error) {
	if data == "" {
		return nil, nil, errors.New("--data is required")
	}
	if err := os.MkdirAll(data, 0o750); err != nil {
		return nil, nil, err
	}
	handBack, err := becomeOwner(data)
	if err != nil {
		return nil, nil, err
	}
	// Runs after the store is closed, so the WAL has been checkpointed and
	// every file the CLI created exists.
	atExit = append(atExit, handBack)
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

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	data := fs.String("data", "", "data directory")
	listen := fs.String("listen", ":8080", "listen address (ignored with --acme-domain, which uses :443 and :80)")
	acme := fs.String("acme-domain", "", "obtain a Let's Encrypt certificate for this domain and serve HTTPS")
	publicURL := fs.String("public-url", "", "origin browsers and devices reach the server at, e.g. https://sync.example.com (default: https://<acme-domain>); names the relying party for the /admin security-key page and completes minted links")
	maxBlob := fs.Int64("max-blob-mb", 1024, "maximum blob size in MiB")
	retention := fs.Duration("retention", 90*24*time.Hour, "keep superseded blobs for this long before GC")
	gcEvery := fs.Duration("gc-interval", 24*time.Hour, "how often to run GC (0 disables)")
	trustProxy := fs.String("trust-proxy", "", "comma-separated CIDRs (or addresses) of reverse proxies whose X-Forwarded-For is trusted; empty: none")
	authRate := fs.Int("auth-rate", 10, "max unauthenticated/failed-auth requests per minute per IP (burst 2x)")
	fs.Parse(args)

	st, bs, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	if *publicURL == "" && *acme != "" {
		*publicURL = "https://" + *acme
	}
	*publicURL = strings.TrimRight(*publicURL, "/")
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if *publicURL != "" {
		// Remembered so `vault create` and `admin register` can print complete
		// links without being told the URL again.
		if err := st.SetSetting(context.Background(), "public_url", *publicURL); err != nil {
			return err
		}
	} else {
		log.Warn("no --public-url: the /admin security-key page is off and the CLI needs --url to print links")
	}
	if keys, err := st.ListAdminCredentials(context.Background()); err == nil && len(keys) == 0 && *publicURL != "" {
		log.Info("admin page has no security key yet; run `obsync admin register --data " + *data + "` to add one")
	}
	srv := api.New(api.Config{PublicURL: *publicURL, MaxBlobSize: *maxBlob << 20, Logger: log, TrustedProxies: strings.Split(*trustProxy, ","), AuthRatePerMinute: *authRate, AuthBurst: *authRate * 2}, st, bs)

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
		// A whole request or response, blob bodies included, must finish in
		// this time: a client trickling one byte a minute does not hold a
		// goroutine and a descriptor for ever.
		ReadTimeout:  15 * time.Minute,
		WriteTimeout: 15 * time.Minute,
	}
	errc := make(chan error, 1)
	if *acme != "" {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*acme),
			Cache:      autocert.DirCache(filepath.Join(*data, "acme")),
		}
		h.Addr = ":443"
		h.TLSConfig = &tls.Config{
			GetCertificate: m.GetCertificate,
			MinVersion:     tls.VersionTLS12,
			// AEAD suites only: Go's default list still offers CBC-SHA1 for TLS 1.2.
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		}
		h.Handler = hsts(srv)
		// The ACME and redirect listener answers nothing worth waiting for.
		plain := &http.Server{Addr: ":80", Handler: m.HTTPHandler(nil), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
		go func() { errc <- plain.ListenAndServe() }()
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
	urlFlag := fs.String("url", "", "the server's public URL (default: the one `serve` was last started with)")
	ttl := fs.Duration("ttl", time.Hour, "how long the link stays redeemable")
	fs.Parse(args[1:])
	st, _, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch args[0] {
	case "create":
		// A create link, not a vault: the vault comes into being when the
		// first device redeems the link, with keys that device made itself.
		server, err := publicURLFor(ctx, st, *urlFlag)
		if err != nil {
			return err
		}
		l, err := st.CreateLink(ctx, store.LinkCreate, "cli", *ttl)
		if err != nil {
			return err
		}
		link := api.CreateLink(server, l.Token)
		code, err := qr.Terminal(api.OpenURL(link))
		if err != nil {
			return err
		}
		fmt.Printf("Create link for one new vault, valid until %s, single use.\n\n", time.UnixMilli(l.ExpiresAt).Format(time.RFC1123))
		fmt.Printf("  %s\n\n", link)
		fmt.Print("Paste it into Settings → obsync → Create a new vault on the first device,\nor scan this with the device's camera:\n\n")
		fmt.Print(code)
	case "list":
		vs, err := st.ListVaults(ctx)
		if err != nil {
			return err
		}
		for _, v := range vs {
			auth := "authority=yes"
			if !v.HasAuth {
				auth = "authority=NONE (run vault auth)"
			}
			fmt.Printf("%s\tdevices=%d\tepoch=%d\tseq=%d\tcreated=%s\t%s\n", v.ID, v.Devices, v.Epoch, v.Seq, time.UnixMilli(v.CreatedAt).Format(time.RFC3339), auth)
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
		if err := st.SetVaultAuth(ctx, rest[0], rest[1]); err != nil {
			return err
		}
		fmt.Println("vault authority set")
	default:
		return errors.New("vault create|list|auth")
	}
	return nil
}

// adminCmd manages the security keys that may sign in to /admin.
func adminCmd(args []string) error {
	if len(args) < 1 {
		return errors.New("admin register|keys|remove|forget")
	}
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	data := fs.String("data", "", "data directory")
	urlFlag := fs.String("url", "", "the server's public URL (default: the one `serve` was last started with)")
	ttl := fs.Duration("ttl", time.Hour, "how long the register link stays usable")
	fs.Parse(args[1:])
	st, _, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch args[0] {
	case "register":
		server, err := publicURLFor(ctx, st, *urlFlag)
		if err != nil {
			return err
		}
		l, err := st.CreateLink(ctx, store.LinkRegister, "cli", *ttl)
		if err != nil {
			return err
		}
		fmt.Printf("Open this in a browser with your security key at hand (valid until %s, single use):\n\n  %s\n\n", time.UnixMilli(l.ExpiresAt).Format(time.RFC1123), api.RegisterURL(server, l.Token))
		fmt.Println("The page asks you to touch the key; give it a name you will recognise. If a key is registered already, the page also offers to sign in with it, which lets this browser in without adding a key. To anyone without such a link, /admin is a 404.")
		fmt.Println("Register a second key the same way, so losing one does not lock you out of the page (the CLI always works).")
	case "keys":
		keys, err := st.ListAdminCredentials(ctx)
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			fmt.Println("no security keys registered; run `obsync admin register`")
		}
		for _, k := range keys {
			last := "never"
			if k.LastUsed > 0 {
				last = time.UnixMilli(k.LastUsed).Format(time.RFC3339)
			}
			fmt.Printf("%s\tregistered=%s\tlast_used=%s\n", k.Name, time.UnixMilli(k.CreatedAt).Format(time.RFC3339), last)
		}
	case "remove":
		rest := fs.Args()
		if len(rest) != 1 {
			return errors.New("admin remove --data DIR NAME")
		}
		if err := st.RemoveAdminCredential(ctx, rest[0]); err != nil {
			return err
		}
		fmt.Println("removed; any open admin session ends when the server restarts or its 15 minutes run out")
	case "forget":
		n, err := st.ForgetAdminBrowsers(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("forgot %d browser(s); /admin is a 404 to every browser until it follows a new register link\n", n)
	default:
		return errors.New("admin register|keys|remove|forget")
	}
	return nil
}

// publicURLFor is the --url flag, else the URL `serve` recorded.
func publicURLFor(ctx context.Context, st *store.Store, flagVal string) (string, error) {
	if flagVal != "" {
		return strings.TrimRight(flagVal, "/"), nil
	}
	v, err := st.GetSetting(ctx, "public_url")
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", errors.New("the server has not been started with --public-url yet; pass --url https://your.host")
	}
	return v, nil
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
	srv := api.New(api.Config{}, st, bs)
	n, err := srv.GC(context.Background(), *retention)
	if err != nil {
		return err
	}
	fmt.Printf("removed %d blobs\n", n)
	return nil
}

// hsts adds Strict-Transport-Security on the TLS listener, so a client that
// once reached the server over https will not try http for two years.
func hsts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		next.ServeHTTP(w, r)
	})
}
