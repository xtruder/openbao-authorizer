// Command server runs the OpenBao control-group approval web application.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/offlinehq/openbao-authorizer/internal/config"
	"github.com/offlinehq/openbao-authorizer/internal/httpapi"
	"github.com/offlinehq/openbao-authorizer/internal/openbao"
	"github.com/offlinehq/openbao-authorizer/internal/push"
	"github.com/offlinehq/openbao-authorizer/internal/scanner"
	"github.com/offlinehq/openbao-authorizer/internal/store"
	frontend "github.com/offlinehq/openbao-authorizer/web"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	httpClient, err := openBaoHTTPClient(cfg.OpenBaoCAFile)
	if err != nil {
		return err
	}
	bao, err := openbao.New(openbao.Config{
		Address:      cfg.OpenBaoAddress,
		ScannerToken: cfg.OpenBaoScannerToken,
		Namespace:    cfg.OpenBaoNamespace,
		HTTPClient:   httpClient,
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

	events := httpapi.NewEventBus()
	sessions := httpapi.NewSessions()
	if deleteExpiredErr := database.DeleteExpiredSessions(context.Background(), time.Now()); deleteExpiredErr != nil {
		return deleteExpiredErr
	}
	storedSessions, err := database.Sessions(context.Background(), time.Now())
	if err != nil {
		return err
	}
	sessions.Restore(storedSessions)
	pushService, err := push.New(database, push.Config{
		PublicKey: cfg.VAPIDPublicKey, PrivateKey: cfg.VAPIDPrivateKey, Subject: cfg.VAPIDSubject,
		AllowedHostSuffixes: cfg.PushAllowedHosts,
		Eligible: func(ctx context.Context, entityID string) bool {
			tokens := sessions.ActiveTokens(entityID)
			if len(tokens) == 0 {
				return false
			}
			// Deliver only when at least one active session still presents a
			// valid, eligible OpenBao token. Transient lookup failures must not
			// delete sessions or subscriptions.
			for _, token := range tokens {
				identity, lookupErr := bao.LookupSelf(ctx, token)
				if lookupErr != nil {
					if isAuthoritativeTokenError(lookupErr) {
						continue
					}
					return true
				}
				if identity.EntityID == entityID && identity.HasPolicy(cfg.ApproverPolicy) {
					return true
				}
			}
			sessions.DeleteEntity(entityID)
			for _, token := range tokens {
				if deleteErr := database.DeleteSessionsByToken(ctx, token); deleteErr != nil {
					logger.Error("delete ineligible durable sessions", "error", deleteErr)
				}
			}
			if deleteErr := database.DeleteSubscriptionsByEntity(ctx, entityID); deleteErr != nil {
				logger.Error("delete ineligible push subscriptions", "error", deleteErr)
			}
			return false
		},
	}, nil)
	if err != nil {
		return err
	}
	notifier := &notificationFanout{events: events, push: pushService}
	accessorScanner := scanner.New(bao, database, notifier, cfg.ScanConcurrency)

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go scanLoop(rootCtx, logger, accessorScanner, cfg.ScanInterval)
	go apiSweeper(rootCtx, logger, sessions, database)
	go sessionRenewalLoop(rootCtx, logger, sessions, bao, database)

	api := httpapi.New(httpapi.Options{
		OpenBao:              bao,
		Store:                database,
		Events:               events,
		Logger:               logger,
		PublicOrigin:         cfg.PublicOrigin,
		VAPIDPublicKey:       cfg.VAPIDPublicKey,
		ApproverPolicy:       cfg.ApproverPolicy,
		ExposeRequestData:    cfg.ExposeRequestData,
		InsecureCookies:      cfg.InsecureCookies,
		Sessions:             sessions,
		ValidatePushEndpoint: pushService.ValidateEndpoint,
	})
	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/", staticHandler(staticFileSystem(cfg.StaticDirectory)))

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           requestLogger(logger, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
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

type notificationFanout struct {
	events *httpapi.EventBus
	push   *push.Service
}

func (n *notificationFanout) NewRequest(ctx context.Context, _ string, request openbao.ControlGroupRequest) error {
	eventErr := n.events.Publish("new-request", map[string]string{"status": "pending"})
	pushErr := n.push.NewRequest(ctx, "", request)
	return errors.Join(eventErr, pushErr)
}

func scanLoop(ctx context.Context, logger *slog.Logger, accessorScanner *scanner.Scanner, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		scanCtx, cancel := context.WithTimeout(ctx, interval)
		err := accessorScanner.Scan(scanCtx)
		cancel()
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("accessor scan failed", "error", err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

type tokenRenewer interface {
	RenewSelf(context.Context, string) error
}

func renewSessionTokens(ctx context.Context, renewer tokenRenewer, tokens []string) ([]string, []error) {
	invalid := make([]string, 0)
	renewErrors := make([]error, 0)
	for _, token := range tokens {
		if err := renewer.RenewSelf(ctx, token); err != nil {
			if isAuthoritativeTokenError(err) {
				invalid = append(invalid, token)
				continue
			}
			renewErrors = append(renewErrors, fmt.Errorf("renew OpenBao session token: %w", err))
		}
	}
	return invalid, renewErrors
}

type sessionTokenStore interface {
	DeleteSessionsByToken(context.Context, string) error
	DeleteExpiredSessions(context.Context, time.Time) error
}

func sessionRenewalLoop(ctx context.Context, logger *slog.Logger, sessions *httpapi.Sessions, renewer tokenRenewer, storage sessionTokenStore) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			invalid, renewErrors := renewSessionTokens(ctx, renewer, sessions.AllActiveTokens(now))
			for _, token := range invalid {
				sessions.DeleteToken(token)
				if err := storage.DeleteSessionsByToken(ctx, token); err != nil {
					logger.Error("delete invalid durable sessions", "error", err)
				}
			}
			for _, err := range renewErrors {
				logger.Warn("session token renewal failed; will retry", "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// apiSweeper periodically deletes expired sessions so human OpenBao tokens do
// not remain in process memory after their cookie has disappeared.
func apiSweeper(ctx context.Context, logger *slog.Logger, sessions *httpapi.Sessions, storage sessionTokenStore) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			sessions.DeleteExpired(now)
			if err := storage.DeleteExpiredSessions(ctx, now); err != nil {
				logger.Error("delete expired durable sessions", "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// isAuthoritativeTokenError reports whether OpenBao rejected the token itself,
// as opposed to a transient transport or server failure.
func isAuthoritativeTokenError(err error) bool {
	var httpErr *openbao.HTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	return httpErr.StatusCode == http.StatusForbidden || httpErr.StatusCode == http.StatusBadRequest || httpErr.StatusCode == http.StatusNotFound
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
			return nil, errors.New("OPENBAO_CA_FILE did not contain a valid certificate")
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

func staticHandler(staticFiles fs.FS) http.Handler {
	files := http.FileServerFS(staticFiles)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; worker-src 'self'; manifest-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
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
