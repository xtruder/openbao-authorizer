// Package push delivers generic Web Push notifications for new requests.
package push

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/offlinehq/openbao-authorizer/internal/openbao"
	"github.com/offlinehq/openbao-authorizer/internal/store"
)

// Store supplies encrypted browser subscriptions.
type Store interface {
	Subscriptions(context.Context) ([]store.Subscription, error)
	DeleteSubscription(context.Context, string) error
}

// Resolver resolves push-service hostnames for SSRF checks and pinned dialing.
type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// Config contains VAPID credentials and outbound-network policy.
type Config struct {
	PublicKey           string
	PrivateKey          string
	Subject             string
	AllowedHostSuffixes []string
	Resolver            Resolver
	Eligible            func(context.Context, string) bool
}

// Sender abstracts the webpush library for deterministic tests.
type Sender func(context.Context, []byte, *webpush.Subscription, *webpush.Options) (*http.Response, error)

// Service sends privacy-preserving notifications.
type Service struct {
	store           Store
	config          Config
	send            Sender
	resolver        Resolver
	httpClient      *http.Client
	allowedSuffixes []string
}

// New constructs a push service. VAPID can be disabled by leaving all credentials empty.
func New(storage Store, config Config, sender Sender) (*Service, error) {
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	allowed := make([]string, 0, len(config.AllowedHostSuffixes))
	for _, suffix := range config.AllowedHostSuffixes {
		suffix = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(suffix, ".")))
		if suffix != "" {
			allowed = append(allowed, suffix)
		}
	}
	enabled := config.PublicKey != "" || config.PrivateKey != "" || config.Subject != ""
	if enabled && (config.PublicKey == "" || config.PrivateKey == "" || config.Subject == "") {
		return nil, errors.New("all VAPID settings are required together")
	}
	if enabled && len(allowed) == 0 {
		return nil, errors.New("at least one push endpoint host suffix is required")
	}

	service := &Service{store: storage, config: config, resolver: resolver, allowedSuffixes: allowed}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = service.dialContext
	service.httpClient = &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if sender == nil {
		sender = webpush.SendNotificationWithContext
	}
	service.send = sender
	return service, nil
}

// ValidateEndpoint rejects non-HTTPS, unlisted, or non-public push endpoints.
func (s *Service) ValidateEndpoint(ctx context.Context, rawEndpoint string) error {
	endpoint, err := url.Parse(rawEndpoint)
	if err != nil {
		return fmt.Errorf("parse push endpoint: %w", err)
	}
	if endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return errors.New("push endpoint must be a plain HTTPS URL")
	}
	if port := endpoint.Port(); port != "" && port != "443" {
		return errors.New("push endpoint must use HTTPS port 443")
	}
	host := strings.ToLower(strings.TrimSuffix(endpoint.Hostname(), "."))
	if !s.allowedHost(host) {
		return errors.New("push endpoint host is not allowlisted")
	}
	addresses, err := s.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve push endpoint: %w", err)
	}
	if len(addresses) == 0 {
		return errors.New("push endpoint did not resolve")
	}
	for _, address := range addresses {
		if !isPublicIP(address.IP) {
			return errors.New("push endpoint resolved to a non-public address")
		}
	}
	return nil
}

func (s *Service) allowedHost(host string) bool {
	for _, suffix := range s.allowedSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func (s *Service) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse outbound address: %w", err)
	}
	if !s.allowedHost(strings.ToLower(strings.TrimSuffix(host, "."))) {
		return nil, errors.New("outbound push host is not allowlisted")
	}
	addresses, err := s.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound push host: %w", err)
	}
	if len(addresses) == 0 {
		return nil, errors.New("outbound push host did not resolve")
	}
	for _, address := range addresses {
		if !isPublicIP(address.IP) {
			return nil, errors.New("outbound push host resolved to a non-public address")
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
}

func isPublicIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range deniedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// NewRequest sends a generic hint; sensitive request details remain in the authenticated app.
func (s *Service) NewRequest(ctx context.Context, _ string, _ openbao.ControlGroupRequest) error {
	if s.config.PublicKey == "" {
		return nil
	}
	subscriptions, err := s.store.Subscriptions(ctx)
	if err != nil {
		return fmt.Errorf("load push subscriptions: %w", err)
	}
	payload, err := json.Marshal(map[string]string{
		"title": "OpenBao approval pending",
		"body":  "A new control-group request needs review.",
		"url":   "/",
	})
	if err != nil {
		return fmt.Errorf("encode push payload: %w", err)
	}

	var sendErrors []error
	for _, subscription := range subscriptions {
		if s.config.Eligible == nil || !s.config.Eligible(ctx, subscription.EntityID) {
			continue
		}
		if validateErr := s.ValidateEndpoint(ctx, subscription.Endpoint); validateErr != nil {
			if deleteErr := s.store.DeleteSubscription(ctx, subscription.Endpoint); deleteErr != nil {
				sendErrors = append(sendErrors, deleteErr)
			}
			continue
		}
		response, sendErr := s.send(ctx, payload, &webpush.Subscription{
			Endpoint: subscription.Endpoint,
			Keys: webpush.Keys{
				P256dh: subscription.P256DH,
				Auth:   subscription.Auth,
			},
		}, &webpush.Options{
			HTTPClient:      s.httpClient,
			Subscriber:      s.config.Subject,
			VAPIDPublicKey:  s.config.PublicKey,
			VAPIDPrivateKey: s.config.PrivateKey,
			TTL:             300,
		})
		if sendErr != nil {
			sendErrors = append(sendErrors, fmt.Errorf("send push: %w", sendErr))
			continue
		}
		if response != nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
				if deleteErr := s.store.DeleteSubscription(ctx, subscription.Endpoint); deleteErr != nil {
					sendErrors = append(sendErrors, deleteErr)
				}
				continue
			}
			if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
				sendErrors = append(sendErrors, fmt.Errorf("push service returned HTTP %d", response.StatusCode))
			}
		}
	}
	return errors.Join(sendErrors...)
}
