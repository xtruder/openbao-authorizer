package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	openbao "github.com/openbao/openbao/api/v2"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/durationpb"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
	"github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1/authorizerv1connect"
)

const (
	stateApproved       = "approved"
	stateAlreadyGranted = "already_granted"
	statePending        = "pending"

	maxAuthorizerResponseBytes = 1 << 20
	// requestTimeout bounds each unary authorizer call so a stalled
	// connection fails instead of hanging until the overall timeout.
	requestTimeout = 30 * time.Second
)

// Package variables so tests can shorten the waits.
var (
	// streamIdleTimeout treats a watch stream as dropped when neither a
	// snapshot nor one of the server's 25s heartbeats arrived in time.
	streamIdleTimeout = time.Minute
	retryDelay        = time.Second
	maxRetryDelay     = 30 * time.Second
	noticeInterval    = 5 * time.Minute
)

var (
	errStreamIdle       = errors.New("watch stream went idle")
	errInsecureRedirect = errors.New("refusing redirect to an insecure authorizer URL")
)

// grantItem is the printed form of a Permission Item; it keeps the JSON shape
// of the former REST API so scripts parsing stdout keep working.
type grantItem struct {
	ID           string     `json:"id"`
	Path         string     `json:"path"`
	Capabilities []string   `json:"capabilities"`
	TTL          string     `json:"ttl,omitempty"`
	State        string     `json:"state"`
	Reason       string     `json:"reason,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

func (i grantItem) label() string {
	return i.Path + "=" + strings.Join(i.Capabilities, ",")
}

type grantRequest struct {
	ID    string      `json:"id"`
	Items []grantItem `json:"items"`
}

func newGrantRequest(message *authorizerv1.GrantRequest) grantRequest {
	request := grantRequest{ID: message.GetId(), Items: make([]grantItem, 0, len(message.GetItems()))}
	for _, item := range message.GetItems() {
		printed := grantItem{
			ID: item.GetId(), Path: item.GetPath(), Capabilities: item.GetCapabilities(),
			State: itemState(item.GetState()), Reason: item.GetReason(),
		}
		if item.GetTtl() != nil {
			printed.TTL = item.GetTtl().AsDuration().String()
		}

		if item.GetExpiresAt() != nil {
			expiresAt := item.GetExpiresAt().AsTime()
			printed.ExpiresAt = &expiresAt
		}

		request.Items = append(request.Items, printed)
	}

	return request
}

// itemState prints ITEM_STATE_ALREADY_GRANTED as already_granted.
func itemState(state authorizerv1.ItemState) string {
	return strings.ToLower(strings.TrimPrefix(state.String(), "ITEM_STATE_"))
}

func (r grantRequest) pendingCount() int {
	count := 0
	for _, item := range r.Items {
		if item.State == statePending {
			count++
		}
	}

	return count
}

// outcomeError maps item states to the documented exit statuses. Pending wins
// over denial because the request is not finished and can still be resumed.
// waited is zero when bao-cred did not wait at all.
func (r grantRequest) outcomeError(waited time.Duration) error {
	if pending := r.pendingCount(); pending > 0 {
		if waited == 0 {
			return &exitError{code: exitPending, err: fmt.Errorf(
				"%d Permission Item(s) pending; wait with: bao-cred request --wait %s", pending, r.ID,
			)}
		}

		return &exitError{code: exitPending, err: fmt.Errorf(
			"%d Permission Item(s) still pending after %s; resume with: bao-cred request --wait %s", pending, waited, r.ID,
		)}
	}

	var denied []string
	for _, item := range r.Items {
		if item.State == stateApproved || item.State == stateAlreadyGranted {
			continue
		}

		denied = append(denied, describeItem(item))
	}

	if len(denied) > 0 {
		return &exitError{code: exitNotGranted, err: fmt.Errorf("not granted: %s", strings.Join(denied, "; "))}
	}

	return nil
}

func describeItem(item grantItem) string {
	description := item.label() + ": " + item.State
	if item.Reason != "" {
		description += " (" + item.Reason + ")"
	}

	return description
}

// grantOutput is the printed form of a Grant.
type grantOutput struct {
	ID           string    `json:"id"`
	ItemID       string    `json:"item_id"`
	Path         string    `json:"path"`
	Capabilities []string  `json:"capabilities"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// authorizerError is an RPC failure reduced to the authorizer's stable reason
// and message. It never includes request headers, so the token stays out of
// output.
type authorizerError struct {
	code    connect.Code
	reason  string
	message string
	// wire is set when the server sent the error, rather than the client
	// deriving it from a failed connection.
	wire bool
	// permanent marks connection failures that reconnecting cannot fix: an
	// untrusted certificate or a refused downgrade redirect.
	permanent bool
}

func (e *authorizerError) Error() string {
	switch e.reason {
	case "INVALID_TOKEN":
		return "the authorizer rejected the token; it may be expired or revoked"
	case "NOT_REQUESTER":
		return "this token is not allowed to request grants (no matching requester rule)"
	case "NOT_FOUND":
		return "not found for this Requester"
	case "OPENBAO_UNAVAILABLE":
		return "the authorizer cannot reach OpenBao; try again later"
	}

	if !e.wire {
		return "authorizer connection failed: " + e.message
	}

	if e.message == "" {
		return "authorizer returned " + e.code.String()
	}

	return fmt.Sprintf("authorizer returned %s: %s", e.code, e.message)
}

func newAuthorizerError(err error) error {
	connectErr, ok := errors.AsType[*connect.Error](err)
	if !ok {
		return err
	}

	result := &authorizerError{code: connectErr.Code(), message: connectErr.Message(), wire: connect.IsWireError(connectErr)}
	result.permanent = !result.wire && (errors.Is(err, errInsecureRedirect) || tlsVerificationError(err))
	for _, detail := range connectErr.Details() {
		value, valueErr := detail.Value()
		if errorDetail, isErrorDetail := value.(*authorizerv1.ErrorDetail); valueErr == nil && isErrorDetail {
			result.reason = errorDetail.GetReason()
			break
		}
	}

	return result
}

// transientAuthorizerError reports whether reconnecting may help.
func transientAuthorizerError(err error) bool {
	if errors.Is(err, errStreamIdle) {
		return true
	}

	rpcErr, ok := errors.AsType[*authorizerError](err)
	if !ok || rpcErr.permanent {
		return false
	}

	// connect-go reports a stream cut mid-message as a client-side
	// invalid_argument protocol error, so only the server's own
	// invalid_argument is final.
	if rpcErr.code == connect.CodeInvalidArgument && !rpcErr.wire {
		return true
	}

	return slices.Contains([]connect.Code{
		connect.CodeUnavailable, connect.CodeUnknown, connect.CodeInternal, connect.CodeDeadlineExceeded,
		connect.CodeResourceExhausted, connect.CodeAborted,
	}, rpcErr.code)
}

func tlsVerificationError(err error) bool {
	_, verification := errors.AsType[*tls.CertificateVerificationError](err)
	_, unknownAuthority := errors.AsType[x509.UnknownAuthorityError](err)
	_, hostname := errors.AsType[x509.HostnameError](err)
	_, invalid := errors.AsType[x509.CertificateInvalidError](err)
	return verification || unknownAuthority || hostname || invalid
}

type authorizerClient struct {
	http    *http.Client
	service authorizerv1connect.GrantServiceClient
}

func newAuthorizerClient(explicitURL, token string) (*authorizerClient, error) {
	raw := strings.TrimSpace(explicitURL)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("BAO_AUTHORIZER_ADDR"))
	}

	if raw == "" {
		return nil, errors.New("authorizer URL is required; use --authorizer or set BAO_AUTHORIZER_ADDR")
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("authorizer URL must be an absolute HTTP or HTTPS URL")
	}

	if !secureAuthorizerURL(parsed) {
		return nil, errors.New("authorizer URL must use HTTPS unless its host is loopback; the token would be sent in clear text")
	}

	httpClient, err := authorizerHTTPClient()
	if err != nil {
		return nil, err
	}

	service := authorizerv1connect.NewGrantServiceClient(
		httpClient, parsed.JoinPath("api").String(),
		connect.WithInterceptors(bearerInterceptor(token)),
		connect.WithReadMaxBytes(maxAuthorizerResponseBytes),
	)

	return &authorizerClient{http: httpClient, service: service}, nil
}

// bearerInterceptor authenticates every unary and streaming call with the
// Requester's token.
type bearerInterceptor string

func (t bearerInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
		request.Header().Set("Authorization", "Bearer "+string(t))
		return next(ctx, request)
	}
}

func (t bearerInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		conn.RequestHeader().Set("Authorization", "Bearer "+string(t))

		return conn
	}
}

func (bearerInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

// secureAuthorizerURL allows plain HTTP only to loopback hosts, where the
// token never crosses a network.
func secureAuthorizerURL(endpoint *url.URL) bool {
	if endpoint.Scheme == "https" {
		return true
	}

	host := endpoint.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// authorizerHTTPClient trusts the system roots plus any CA configured for
// OpenBao through BAO_CACERT, BAO_CACERT_BYTES, or BAO_CAPATH. The OpenBao
// client trusts only the configured CA; adding to the system pool instead lets
// the authorizer sit behind either a public or the same private CA.
// BAO_SKIP_VERIFY is deliberately not honored for the authorizer.
func authorizerHTTPClient() (*http.Client, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected default HTTP transport")
	}

	transport = transport.Clone()
	pool, err := extraRootCAs()
	if err != nil {
		return nil, err
	}

	if pool != nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}

	return &http.Client{Transport: transport, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		// Redirects keep the Authorization header on the same host, so a
		// downgrade to plain HTTP would leak the token.
		if !secureAuthorizerURL(request.URL) {
			return errInsecureRedirect
		}

		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}

		return nil
	}}, nil
}

func extraRootCAs() (*x509.CertPool, error) {
	caCert := openbao.ReadBaoVariable(openbao.EnvVaultCACert)
	caBytes := openbao.ReadBaoVariable(openbao.EnvVaultCACertBytes)
	caPath := openbao.ReadBaoVariable(openbao.EnvVaultCAPath)
	if caCert == "" && caBytes == "" && caPath == "" {
		return nil, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}

	if caCert != "" {
		// #nosec G304 -- the CA path is explicitly configured by the user.
		contents, readErr := os.ReadFile(caCert)
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", openbao.EnvVaultCACert, readErr)
		}

		if !pool.AppendCertsFromPEM(contents) {
			return nil, fmt.Errorf("%s contains no PEM certificates", openbao.EnvVaultCACert)
		}
	}

	if caBytes != "" && !pool.AppendCertsFromPEM([]byte(caBytes)) {
		return nil, fmt.Errorf("%s contains no PEM certificates", openbao.EnvVaultCACertBytes)
	}

	if caPath != "" {
		entries, readErr := os.ReadDir(caPath)
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", openbao.EnvVaultCAPath, readErr)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			// #nosec G304 -- files come from the explicitly configured CA directory.
			contents, fileErr := os.ReadFile(filepath.Join(caPath, entry.Name()))
			if fileErr != nil {
				return nil, fmt.Errorf("read %s: %w", openbao.EnvVaultCAPath, fileErr)
			}

			pool.AppendCertsFromPEM(contents)
		}
	}

	return pool, nil
}

func (c *authorizerClient) createGrantRequest(
	ctx context.Context, input *authorizerv1.CreateGrantRequestRequest,
) (grantRequest, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	response, err := c.service.CreateGrantRequest(ctx, connect.NewRequest(input))
	if err != nil {
		return grantRequest{}, fmt.Errorf("file Grant Request: %w", newAuthorizerError(err))
	}

	request := newGrantRequest(response.Msg.GetGrantRequest())
	if request.ID == "" {
		return grantRequest{}, errors.New("file Grant Request: authorizer returned no request id")
	}

	return request, nil
}

func (c *authorizerClient) grantRequest(ctx context.Context, id string) (grantRequest, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	response, err := c.service.GetGrantRequest(ctx, connect.NewRequest(&authorizerv1.GetGrantRequestRequest{Id: id}))
	if err != nil {
		return grantRequest{}, fmt.Errorf("read Grant Request %s: %w", id, newAuthorizerError(err))
	}

	request := newGrantRequest(response.Msg.GetGrantRequest())
	if request.ID == "" {
		request.ID = id
	}

	return request, nil
}

// watchGrantRequest calls onSnapshot for every snapshot on one watch stream
// and onMessage for every message, heartbeats included. It returns nil when
// the server ends the stream normally.
func (c *authorizerClient) watchGrantRequest(
	ctx context.Context, id string, onSnapshot func(grantRequest), onMessage func(),
) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	idle := time.AfterFunc(streamIdleTimeout, func() { cancel(errStreamIdle) })
	defer idle.Stop()
	stream, err := c.service.WatchGrantRequest(ctx, connect.NewRequest(&authorizerv1.WatchGrantRequestRequest{Id: id}))
	if err != nil {
		return fmt.Errorf("watch Grant Request %s: %w", id, newAuthorizerError(err))
	}

	defer func() { _ = stream.Close() }()
	for stream.Receive() {
		idle.Reset(streamIdleTimeout)
		if snapshot := stream.Msg().GetGrantRequest(); snapshot != nil {
			request := newGrantRequest(snapshot)
			if request.ID == "" {
				request.ID = id
			}

			onSnapshot(request)
		}

		onMessage()
	}

	if errors.Is(context.Cause(ctx), errStreamIdle) {
		return fmt.Errorf("watch Grant Request %s: %w", id, errStreamIdle)
	}

	if err := stream.Err(); err != nil {
		return fmt.Errorf("watch Grant Request %s: %w", id, newAuthorizerError(err))
	}

	return nil
}

func (c *authorizerClient) grants(ctx context.Context) ([]grantOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	response, err := c.service.ListMyGrants(ctx, connect.NewRequest(&authorizerv1.ListMyGrantsRequest{}))
	if err != nil {
		return nil, fmt.Errorf("list Grants: %w", newAuthorizerError(err))
	}

	grants := make([]grantOutput, 0, len(response.Msg.GetGrants()))
	for _, grant := range response.Msg.GetGrants() {
		grants = append(grants, grantOutput{
			ID: grant.GetId(), ItemID: grant.GetItemId(), Path: grant.GetPath(), Capabilities: grant.GetCapabilities(),
			CreatedAt: grant.GetCreatedAt().AsTime(), ExpiresAt: grant.GetExpiresAt().AsTime(),
		})
	}

	return grants, nil
}

// waitForGrantRequest watches the request until no item is pending or timeout
// elapses, reconnecting with capped backoff after drops. Each snapshot is the
// full truth, so nothing is lost across reconnects. Reaching the timeout is
// not an error: the returned request still has pending items, which
// outcomeError reports.
func waitForGrantRequest(
	ctx context.Context, client *authorizerClient, request grantRequest, timeout time.Duration, progress progressFunc,
) (grantRequest, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lastNotice := time.Now()
	delay := retryDelay
	seen := make(map[string]string, len(request.Items))
	reportChanges(request, seen, progress)
	onSnapshot := func(next grantRequest) {
		request = next
		reportChanges(request, seen, progress)
	}
	onMessage := func() {
		delay = retryDelay
		if pending := request.pendingCount(); pending > 0 && time.Since(lastNotice) >= noticeInterval {
			lastNotice = time.Now()
			progress(fmt.Sprintf("still waiting for %d Permission Item(s) in Grant Request %s", pending, request.ID))
		}
	}

	for request.pendingCount() > 0 {
		err := client.watchGrantRequest(waitCtx, request.ID, onSnapshot, onMessage)
		if ctx.Err() != nil {
			return request, fmt.Errorf("stopped waiting: %w; resume with: bao-cred request --wait %s", ctx.Err(), request.ID)
		}

		if waitCtx.Err() != nil {
			return request, nil
		}

		if err == nil {
			if request.pendingCount() == 0 {
				break
			}

			err = errors.New("watch stream ended with Permission Items still pending")
		} else if !transientAuthorizerError(err) {
			return request, fmt.Errorf("%w; resume with: bao-cred request --wait %s", err, request.ID)
		}

		progress(fmt.Sprintf("%v; reconnecting in %s", err, delay))
		select {
		case <-waitCtx.Done():
		case <-time.After(delay):
		}

		delay = min(delay*2, maxRetryDelay)
	}

	return request, nil
}

func reportChanges(request grantRequest, seen map[string]string, progress progressFunc) {
	for _, item := range request.Items {
		if seen[item.ID] == item.State {
			continue
		}

		seen[item.ID] = item.State
		if item.State != statePending {
			progress(describeItem(item))
		}
	}
}

type requestFlags struct {
	reason     string
	items      []string
	ttl        time.Duration
	timeout    time.Duration
	noWait     bool
	waitID     string
	authorizer string
	quiet      bool
}

func newRequestCommand() *cobra.Command {
	var flags requestFlags
	command := &cobra.Command{
		Use:   "request --reason TEXT --item PATH=CAPS [--item ...] | --wait ID",
		Short: "File a Grant Request and wait for an Approver",
		Long: `Files a Grant Request for one or more Permission Items and waits until none
is pending, or resumes waiting on an existing request with --wait. Prints the
request as JSON on stdout.`,
		Example: `  bao-cred request --reason "migrate app schema" --item database/creds/app=read --item kv/data/app=read,update
  bao-cred request --no-wait --reason "rotate the CI token" --item github/token/project-ci=read
  bao-cred request --wait <request-id>`,
		Args: noPositionalArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runRequest(command.Context(), flags, command.OutOrStdout(), command.ErrOrStderr())
		},
	}

	set := command.Flags()
	set.StringVar(&flags.reason, "reason", "", "why the Requester needs access (required)")
	// StringArray, unlike StringSlice, keeps the commas between capabilities.
	set.StringArrayVar(&flags.items, "item", nil,
		"Permission Item PATH=CAP[,CAP]; CAP is create, read, update, patch, delete, or list; repeatable")
	set.DurationVar(&flags.ttl, "ttl", 0, "requested Grant lifetime for every item")
	set.DurationVar(&flags.timeout, "timeout", 15*time.Minute, "approval wait timeout")
	set.BoolVar(&flags.noWait, "no-wait", false, "print the filed request without waiting")
	set.StringVar(&flags.waitID, "wait", "", "resume waiting on an existing Grant Request")
	set.StringVar(&flags.authorizer, "authorizer", "", "authorizer base URL (default $BAO_AUTHORIZER_ADDR)")
	set.BoolVar(&flags.quiet, "quiet", false, "suppress progress messages")
	return command
}

func noPositionalArgs(command *cobra.Command, arguments []string) error {
	if len(arguments) != 0 {
		return usageError(fmt.Errorf("%s accepts no positional arguments", command.Name()))
	}

	return nil
}

func runRequest(ctx context.Context, flags requestFlags, stdout, stderr io.Writer) error {
	if flags.timeout <= 0 || flags.ttl < 0 {
		return usageError(errors.New("timeout must be positive and ttl must not be negative"))
	}

	input := &authorizerv1.CreateGrantRequestRequest{Reason: strings.TrimSpace(flags.reason)}
	id := strings.TrimSpace(flags.waitID)
	if id != "" {
		if input.Reason != "" || len(flags.items) > 0 || flags.ttl != 0 || flags.noWait {
			return usageError(errors.New("--wait cannot be combined with --reason, --item, --ttl, or --no-wait"))
		}
	} else {
		if input.Reason == "" {
			return usageError(errors.New("--reason is required"))
		}

		if len(flags.items) == 0 {
			return usageError(errors.New("at least one --item is required"))
		}

		for _, raw := range flags.items {
			item, err := parseItem(raw, flags.ttl)
			if err != nil {
				return usageError(err)
			}

			input.Items = append(input.Items, item)
		}
	}

	token, err := requesterToken()
	if err != nil {
		return err
	}

	client, err := newAuthorizerClient(flags.authorizer, token)
	if err != nil {
		return err
	}

	progress := newProgress(stderr, flags.quiet)
	var request grantRequest
	if id != "" {
		request, err = client.grantRequest(ctx, id)
		if err != nil {
			return err
		}

		progress("waiting on Grant Request " + request.ID)
	} else {
		request, err = client.createGrantRequest(ctx, input)
		if err != nil {
			return err
		}

		progress("filed Grant Request " + request.ID)
	}

	var waited time.Duration
	if !flags.noWait {
		waited = flags.timeout
		request, err = waitForGrantRequest(ctx, client, request, flags.timeout, progress)
		if err != nil {
			return err
		}
	}

	if err := writeIndentedJSON(stdout, request); err != nil {
		return err
	}

	return request.outcomeError(waited)
}

func parseItem(value string, ttl time.Duration) (*authorizerv1.PermissionItemInput, error) {
	// Capabilities never contain "=", so splitting at the last one keeps any
	// "=" inside the path.
	index := strings.LastIndexByte(value, '=')
	path := ""
	if index > 0 {
		path = strings.TrimSpace(value[:index])
	}

	if path == "" {
		return nil, fmt.Errorf("item must be PATH=CAP[,CAP]: %q", value)
	}

	var capabilities []string
	for capability := range strings.SplitSeq(value[index+1:], ",") {
		capability = strings.TrimSpace(capability)
		if capability == "" {
			return nil, fmt.Errorf("item must be PATH=CAP[,CAP]: %q", value)
		}

		capabilities = append(capabilities, capability)
	}

	item := &authorizerv1.PermissionItemInput{Path: path, Capabilities: capabilities}
	if ttl > 0 {
		item.Ttl = durationpb.New(ttl)
	}

	return item, nil
}

func newGrantsCommand() *cobra.Command {
	var authorizerURL string
	command := &cobra.Command{
		Use:   "grants",
		Short: "List the Requester's active Grants as JSON",
		Args:  noPositionalArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runGrants(command.Context(), authorizerURL, command.OutOrStdout())
		},
	}

	command.Flags().StringVar(&authorizerURL, "authorizer", "", "authorizer base URL (default $BAO_AUTHORIZER_ADDR)")
	return command
}

func runGrants(ctx context.Context, authorizerURL string, stdout io.Writer) error {
	token, err := requesterToken()
	if err != nil {
		return err
	}

	client, err := newAuthorizerClient(authorizerURL, token)
	if err != nil {
		return err
	}

	grants, err := client.grants(ctx)
	if err != nil {
		return err
	}

	return writeIndentedJSON(stdout, grants)
}

func writeIndentedJSON(output io.Writer, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}

	_, err = output.Write(append(encoded, '\n'))
	return err
}
