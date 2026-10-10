// Command openbao-authorizer runs the OpenBao Authorizer: the Grant API that
// Requesters file Grant Requests with and the Approver PWA that decides them.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/xtruder/openbao-authorizer/internal/api"
	"github.com/xtruder/openbao-authorizer/internal/config"
	"github.com/xtruder/openbao-authorizer/internal/grants"
	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/push"
	"github.com/xtruder/openbao-authorizer/internal/store"
	frontend "github.com/xtruder/openbao-authorizer/web"
)

func main() {
	configPath := flag.String("config", "openbao-authorizer.hcl", "path to the HCL configuration file")
	flag.Parse()
	if err := run(*configPath); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	httpClient, err := openBaoHTTPClient(cfg.OpenBaoCAFile)
	if err != nil {
		return err
	}

	bao, err := openbao.New(openbao.Config{
		Address:    cfg.OpenBaoAddress,
		Token:      cfg.OpenBaoAuthorizerToken,
		Namespace:  cfg.OpenBaoNamespace,
		HTTPClient: httpClient,
	})
	if err != nil {
		return err
	}

	database, err := store.Open(cfg.DatabasePath, cfg.EncryptionKey)
	if err != nil {
		return err
	}

	defer func() {
		if closeErr := database.Close(); closeErr != nil {
			logger.Error("close database", "error", closeErr)
		}
	}()

	events := api.NewEventBus()
	pushService, err := push.New(database, push.Config{
		PublicKey: cfg.VAPIDPublicKey, PrivateKey: cfg.VAPIDPrivateKey, Subject: cfg.VAPIDSubject,
		AllowedHostSuffixes: cfg.PushAllowedHosts,
	}, nil)
	if err != nil {
		return err
	}

	grantService := grants.New(bao, database, &api.Notifier{Events: events, Push: pushService, Logger: logger}, grants.Config{
		Policy:     cfg.GrantPolicy,
		PendingTTL: cfg.PendingTTL,
		Requesters: cfg.Requesters,
		Logger:     logger,
	})

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go grantService.Run(rootCtx)
	go sessionSweeper(rootCtx, logger, database)

	apiHandler := api.New(api.Options{
		OpenBao:              bao,
		Store:                database,
		Grants:               grantService,
		Events:               events,
		Logger:               logger,
		PublicOrigin:         cfg.PublicOrigin,
		VAPIDPublicKey:       cfg.VAPIDPublicKey,
		ApproverPolicy:       cfg.ApproverPolicy,
		ApproverLogin:        cfg.ApproverLogin,
		InsecureCookies:      cfg.InsecureCookies,
		SessionTTL:           cfg.SessionTTL,
		ValidatePushEndpoint: pushService.ValidateEndpoint,
	})
	server := newHTTPServer(cfg.ListenAddress, requestLogger(logger, routes(apiHandler, staticFileSystem(cfg.StaticDirectory), cfg.ApproverLogin.OpenBaoAddress)))
	serveErrors := make(chan error, 1)
	go func() {
		logger.Info("listening", "address", cfg.ListenAddress)
		serveErrors <- server.ListenAndServe()
	}()
	select {
	case err := <-serveErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-rootCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown server: %w", err)
		}
	}

	return nil
}

// newHTTPServer builds the server. Its request contexts are cancelled as soon
// as Shutdown begins: Shutdown only waits for idle connections, and live
// streams would otherwise hold it until the timeout.
func newHTTPServer(address string, handler http.Handler) *http.Server {
	baseCtx, cancel := context.WithCancel(context.Background())
	server := &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
	}
	server.RegisterOnShutdown(cancel)
	return server
}

// routes serves the ConnectRPC services under /api/ next to the health check
// and the PWA.
func routes(apiHandler http.Handler, staticFiles fs.FS, openBaoAddress string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/", staticHandler(staticFiles, openBaoAddress))
	return mux
}

// sessionSweeper periodically deletes expired approver sessions; lookups
// already ignore them, so this only keeps the table small.
func sessionSweeper(ctx context.Context, logger *slog.Logger, storage *store.DB) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			if err := storage.DeleteExpiredSessions(ctx, now); err != nil {
				logger.Error("delete expired sessions", "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func openBaoHTTPClient(caFile string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system CA pool: %w", err)
	}

	if caFile != "" {
		// #nosec G304 -- the CA path is trusted operator configuration.
		certificate, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read OpenBao CA: %w", err)
		}

		if !roots.AppendCertsFromPEM(certificate) {
			return nil, errors.New("openbao.ca_file did not contain a valid certificate")
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, nil
}

func staticFileSystem(directory string) fs.FS {
	if directory != "" {
		return os.DirFS(directory)
	}

	return frontend.Dist
}

// staticHandler serves the PWA. Its CSP lets it reach OpenBao, where Approvers
// sign in directly.
func staticHandler(staticFiles fs.FS, openBaoAddress string) http.Handler {
	files := http.FileServerFS(staticFiles)
	connectSources := "'self'"
	if address, err := url.Parse(openBaoAddress); err == nil && address.Host != "" {
		connectSources += " " + address.Scheme + "://" + address.Host
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src "+connectSources+"; img-src 'self' data:; style-src 'self'; script-src 'self'; worker-src 'self'; manifest-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		requestedPath := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if requestedPath == "" {
			requestedPath = "index.html"
		}

		servedPath := requestedPath
		if info, err := fs.Stat(staticFiles, servedPath); err != nil || info.IsDir() {
			if err != nil && path.Ext(requestedPath) != "" {
				http.NotFound(w, r)
				return
			}

			servedPath = "index.html"
		}

		if extension := path.Ext(servedPath); extension != "" {
			if mediaType := mime.TypeByExtension(extension); mediaType != "" {
				w.Header().Set("Content-Type", mediaType)
			}
		}

		request := r.Clone(r.Context())
		if servedPath == "index.html" {
			request.URL.Path = "/"
		} else {
			request.URL.Path = "/" + servedPath
		}

		files.ServeHTTP(w, request)
	})
}

func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		logger.Info("http request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(started))
	})
}
