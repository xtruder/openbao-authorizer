//go:build e2e && linux

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	rootToken       = "openbao-e2e-root"
	alicePassword   = "alice-e2e-password"
	bobPassword     = "bob-e2e-password"
	requesterPolicy = "e2e-requester"
	approverPolicy  = "e2e-approver"
	servicePolicy   = "e2e-service"
)

func TestOpenBaoControlGroupWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("real-process OpenBao E2E is disabled by -short")
	}

	repositoryRoot := testRepositoryRoot(t)
	cacheRoot := filepath.Join(repositoryRoot, ".e2e", "openbao")
	if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
		t.Fatalf("create E2E cache: %v", err)
	}

	runtimeDirectory, err := os.MkdirTemp(cacheRoot, "runtime.") //nolint:usetesting // Failed E2E runs retain artifacts for diagnosis.
	if err != nil {
		t.Fatalf("create E2E runtime directory: %v", err)
	}

	t.Cleanup(func() {
		if t.Failed() || os.Getenv("OPENBAO_E2E_KEEP_RUNTIME") == "1" {
			t.Logf("runtime artifacts retained at %s", runtimeDirectory)
			return
		}

		if removeErr := os.RemoveAll(runtimeDirectory); removeErr != nil {
			t.Errorf("remove E2E runtime directory: %v", removeErr)
		}
	})
	isolatedHome := filepath.Join(runtimeDirectory, "home")
	temporaryDirectory := filepath.Join(runtimeDirectory, "tmp")
	for _, directory := range []string{isolatedHome, temporaryDirectory, filepath.Join(isolatedHome, ".config")} {
		if mkdirErr := os.MkdirAll(directory, 0o700); mkdirErr != nil {
			t.Fatalf("create isolated process directory: %v", mkdirErr)
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	baoBinary := requiredExecutable(t, "OPENBAO_E2E_BAO_BINARY")

	appBinary := requiredExecutable(t, "OPENBAO_E2E_APP_BINARY")
	processPaths := isolatedProcessPaths{home: isolatedHome, temporary: temporaryDirectory}

	baoLog := filepath.Join(runtimeDirectory, "openbao.log")
	baoProcess, err := startManagedProcess(
		baoLog,
		repositoryRoot,
		processPaths.environment(),
		baoBinary,
		"server",
		"-dev",
		"-dev-root-token-id="+rootToken,
		"-dev-listen-address=127.0.0.1:0",
		"-log-level=warn",
	)
	if err != nil {
		t.Fatalf("start OpenBao: %v", err)
	}

	registerProcessCleanup(t, "OpenBao", baoProcess)
	listenerContext, listenerCancel := context.WithTimeout(ctx, 20*time.Second)
	baoPort, err := waitForOwnedHTTPListener(listenerContext, baoProcess, "/v1/sys/health")
	listenerCancel()
	if err != nil {
		t.Fatalf("wait for OpenBao listener: %v\n%s", err, readProcessLog(baoLog))
	}

	bao := &liveAPI{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d/v1", baoPort),
		client:  &http.Client{Timeout: 15 * time.Second},
		process: baoProcess,
		port:    baoPort,
	}
	mustCall(t, ctx, bao, "", http.MethodGet, "sys/health", nil, http.StatusOK)
	t.Logf("OpenBao process %d owns its kernel-assigned listener", baoProcess.pid)

	mustCall(t, ctx, bao, rootToken, http.MethodPost, "sys/mounts/kv", map[string]any{
		"type": "kv", "options": map[string]string{"version": "2"},
	}, http.StatusOK, http.StatusNoContent)
	mountsResponse := mustCall(t, ctx, bao, rootToken, http.MethodGet, "sys/mounts", nil, http.StatusOK)
	var mountsEnvelope struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	decodeResponse(t, mountsResponse, &mountsEnvelope)
	if _, exists := mountsEnvelope.Data["github/"]; exists {
		t.Fatal("E2E OpenBao unexpectedly has the GitHub plugin mounted")
	}

	t.Log("OpenBao E2E uses built-in mounts only; no GitHub plugin is mounted")
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "sys/auth/userpass", map[string]string{"type": "userpass"}, http.StatusOK, http.StatusNoContent)
	writePolicy(ctx, t, bao, repositoryRoot, requesterPolicy, "requester.hcl")
	writePolicy(ctx, t, bao, repositoryRoot, approverPolicy, "approver.hcl")
	writePolicy(ctx, t, bao, repositoryRoot, servicePolicy, "service.hcl")

	authResponse := mustCall(t, ctx, bao, rootToken, http.MethodGet, "sys/auth", nil, http.StatusOK)
	var authMounts struct {
		Data map[string]struct {
			Accessor string `json:"accessor"`
		} `json:"data"`
	}
	decodeResponse(t, authResponse, &authMounts)
	userpassAccessor := authMounts.Data["userpass/"].Accessor
	if userpassAccessor == "" {
		t.Fatal("userpass mount response omitted its accessor")
	}

	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/userpass/users/alice", map[string]string{"password": alicePassword}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/userpass/users/bob", map[string]string{"password": bobPassword, "token_period": "24h"}, http.StatusOK, http.StatusNoContent)

	aliceEntityID := createEntity(ctx, t, bao, "Alice")
	bobEntityID := createEntity(ctx, t, bao, "Bob")
	createEntityAlias(ctx, t, bao, "alice", userpassAccessor, aliceEntityID)
	createEntityAlias(ctx, t, bao, "bob", userpassAccessor, bobEntityID)
	createIdentityGroup(ctx, t, bao, "e2e-requesters", aliceEntityID, requesterPolicy)
	createIdentityGroup(ctx, t, bao, "e2e-approvers", bobEntityID, approverPolicy)

	alice := loginUserpass(ctx, t, bao, "alice", alicePassword)
	assertIdentityLogin(t, "Alice", alice, aliceEntityID, requesterPolicy)
	bob := loginUserpass(ctx, t, bao, "bob", bobPassword)
	assertIdentityLogin(t, "Bob", bob, bobEntityID, approverPolicy)

	serviceCreate := mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/token/create-orphan", map[string]any{
		"policies": []string{servicePolicy}, "no_default_policy": true, "ttl": "20m",
	}, http.StatusOK)
	var serviceEnvelope loginEnvelope
	decodeResponse(t, serviceCreate, &serviceEnvelope)
	serviceToken := serviceEnvelope.Auth.ClientToken
	if serviceToken == "" {
		t.Fatal("service token creation returned an empty token")
	}

	lookup := mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/token/lookup", map[string]string{"token": serviceToken}, http.StatusOK)
	var lookupEnvelope struct {
		Data struct {
			Policies []string `json:"policies"`
		} `json:"data"`
	}
	decodeResponse(t, lookup, &lookupEnvelope)
	if len(lookupEnvelope.Data.Policies) != 1 || lookupEnvelope.Data.Policies[0] != servicePolicy {
		t.Fatalf("service policies = %v, want only %q", lookupEnvelope.Data.Policies, servicePolicy)
	}

	firstMarker := fmt.Sprintf("first-%d", time.Now().UnixNano())
	secondMarker := fmt.Sprintf("second-%d", time.Now().UnixNano())
	approvedWrappings := []wrappingInfo{
		issueProtectedWrite(ctx, t, bao, alice.Auth.ClientToken, "approved-first", firstMarker),
		issueProtectedWrite(ctx, t, bao, alice.Auth.ClientToken, "approved-second", secondMarker),
	}

	mustCall(t, ctx, bao, rootToken, http.MethodGet, "kv/data/payroll", nil, http.StatusNotFound)

	accessorPayload := map[string]string{"accessor": approvedWrappings[0].Accessor}
	pending := inspectControlGroup(ctx, t, bao, serviceToken, accessorPayload)
	if pending.Approved || pending.RequestPath != "kv/data/payroll" || pending.RequestOperation != "create" || pending.RequestEntity.Name != "Alice" {
		t.Fatalf("unexpected pending request: %+v", pending)
	}

	if pending.RequestData.Data.Marker != firstMarker {
		t.Fatalf("service request marker = %q, want %q", pending.RequestData.Data.Marker, firstMarker)
	}

	mustCall(t, ctx, bao, serviceToken, http.MethodPost, "sys/control-group/authorize", accessorPayload, http.StatusForbidden)
	unchanged := inspectControlGroup(ctx, t, bao, serviceToken, accessorPayload)
	if unchanged.Approved || len(unchanged.Authorizations) != 0 {
		t.Fatalf("denied service authorization changed state: %+v", unchanged)
	}

	revocationProbe := issueProtectedWrite(ctx, t, bao, alice.Auth.ClientToken, "must-not-run", "service-revocation-probe")
	mustCall(t, ctx, bao, serviceToken, http.MethodPost, "auth/token/revoke-accessor", map[string]string{"accessor": revocationProbe.Accessor}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, serviceToken, http.MethodPost, "sys/control-group/request", map[string]string{"accessor": revocationProbe.Accessor}, http.StatusBadRequest, http.StatusNotFound)
	t.Log("least-privilege service token inspected and revoked requests but was denied authorization")

	appLog := filepath.Join(runtimeDirectory, "app.log")
	encryptionKey := make([]byte, 32)
	if _, randomErr := rand.Read(encryptionKey); randomErr != nil {
		t.Fatalf("generate application encryption key: %v", randomErr)
	}

	staticDirectory := filepath.Join(runtimeDirectory, "static")
	if mkdirErr := os.Mkdir(staticDirectory, 0o755); mkdirErr != nil {
		t.Fatalf("create static directory: %v", mkdirErr)
	}

	encryptionKeyFile := filepath.Join(runtimeDirectory, "encryption-key")
	if writeErr := os.WriteFile(encryptionKeyFile, []byte(base64.StdEncoding.EncodeToString(encryptionKey)), 0o600); writeErr != nil {
		t.Fatalf("write encryption key: %v", writeErr)
	}

	serviceTokenFile := filepath.Join(runtimeDirectory, "service-token")
	if writeErr := os.WriteFile(serviceTokenFile, []byte(serviceToken), 0o600); writeErr != nil {
		t.Fatalf("write service token: %v", writeErr)
	}

	appConfig := filepath.Join(runtimeDirectory, "app.hcl")
	configuration := fmt.Sprintf(`
server {
  listen_address   = "127.0.0.1:0"
  public_origin    = ""
  insecure_cookies = true
  static_directory = %q
}
storage {
  database_path       = %q
  encryption_key_file = %q
}
openbao {
  address            = %q
  namespace          = ""
  ca_file            = ""
  service_token_file = %q
  approver_policy    = %q
}
reconciliation {
  interval = "1s"
}
requests {
  expose_data    = false
  require_reason = true
}
`, staticDirectory, filepath.Join(runtimeDirectory, "app.db"), encryptionKeyFile, strings.TrimSuffix(bao.baseURL, "/v1"), serviceTokenFile, approverPolicy)
	if writeErr := os.WriteFile(appConfig, []byte(configuration), 0o600); writeErr != nil {
		t.Fatalf("write application config: %v", writeErr)
	}

	appProcess, err := startManagedProcess(appLog, repositoryRoot, processPaths.environment(), appBinary, "-config", appConfig)
	if err != nil {
		t.Fatalf("start application: %v", err)
	}

	registerProcessCleanup(t, "application", appProcess)
	appListenerContext, appListenerCancel := context.WithTimeout(ctx, 30*time.Second)
	appPort, err := waitForOwnedListener(appListenerContext, appProcess, 0)
	appListenerCancel()
	if err != nil {
		t.Fatalf("wait for application listener: %v\n%s", err, readProcessLog(appLog))
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}

	application := &liveAPI{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", appPort),
		client:  &http.Client{Timeout: 15 * time.Second, Jar: jar},
		process: appProcess,
		port:    appPort,
	}
	mustCall(t, ctx, application, "", http.MethodGet, "healthz", nil, http.StatusOK)
	select {
	case <-time.After(1500 * time.Millisecond):
	case <-ctx.Done():
		t.Fatalf("wait beyond reconciliation interval: %v", ctx.Err())
	}

	loginResponse := mustCall(t, ctx, application, "", http.MethodPost, "api/v1/session", map[string]string{"username": "bob", "password": bobPassword}, http.StatusOK)
	var appSession struct {
		CSRFToken string `json:"csrfToken"`
		Identity  struct {
			EntityID string `json:"entity_id"`
		} `json:"identity"`
	}
	decodeResponse(t, loginResponse, &appSession)
	if appSession.CSRFToken == "" || appSession.Identity.EntityID != bobEntityID {
		t.Fatalf("application login returned unexpected session: %+v", appSession)
	}

	emptyList := mustCall(t, ctx, application, "", http.MethodGet, "api/v1/request-groups", nil, http.StatusOK)
	var groups []applicationRequestGroup
	decodeResponse(t, emptyList, &groups)
	if len(groups) != 0 {
		t.Fatalf("application discovered unsubmitted OpenBao requests: %+v", groups)
	}

	mustCallWithHeaders(t, ctx, application, "", http.MethodDelete, "api/v1/session", map[string]any{}, map[string]string{"X-CSRF-Token": appSession.CSRFToken}, http.StatusNoContent)

	approvedReason := "Apply ordered payroll updates"
	approvedSubmission := map[string]any{
		"idempotencyKey": "e2e-approved-batch",
		"reason":         approvedReason,
		"accessors":      []string{approvedWrappings[0].Accessor, approvedWrappings[1].Accessor},
	}
	createdResponse := mustCall(t, ctx, application, alice.Auth.ClientToken, http.MethodPost, "api/v1/request-groups", approvedSubmission, http.StatusCreated)
	var createdGroup applicationRequestGroup
	decodeResponse(t, createdResponse, &createdGroup)
	if createdGroup.ID == "" || len(createdGroup.Requests) != 2 {
		t.Fatalf("unexpected explicit request-group submission: %+v", createdGroup)
	}

	retryResponse := mustCall(t, ctx, application, alice.Auth.ClientToken, http.MethodPost, "api/v1/request-groups", approvedSubmission, http.StatusOK)
	var retriedGroup applicationRequestGroup
	decodeResponse(t, retryResponse, &retriedGroup)
	if retriedGroup.ID != createdGroup.ID {
		t.Fatalf("idempotent resubmission group ID = %q, want %q", retriedGroup.ID, createdGroup.ID)
	}

	loginResponse = mustCall(t, ctx, application, "", http.MethodPost, "api/v1/session", map[string]string{"username": "bob", "password": bobPassword}, http.StatusOK)
	decodeResponse(t, loginResponse, &appSession)
	if appSession.CSRFToken == "" || appSession.Identity.EntityID != bobEntityID {
		t.Fatalf("application approval login returned unexpected session: %+v", appSession)
	}

	groupsResponse := mustCall(t, ctx, application, "", http.MethodGet, "api/v1/request-groups", nil, http.StatusOK)
	decodeResponse(t, groupsResponse, &groups)
	if len(groups) != 1 {
		t.Fatalf("listed request groups = %+v, want one", groups)
	}

	listedGroup := groups[0]
	if listedGroup.ID != createdGroup.ID || listedGroup.Reason != approvedReason || listedGroup.Status != "pending" || listedGroup.Entity.Name != "userpass-alice" {
		t.Fatalf("unexpected listed request group: %+v", listedGroup)
	}

	if len(listedGroup.Requests) != 2 || listedGroup.Requests[0].Position != 0 || listedGroup.Requests[1].Position != 1 {
		t.Fatalf("listed request members are not in submission order: %+v", listedGroup.Requests)
	}

	if listedGroup.Requests[0].ID != createdGroup.Requests[0].ID || listedGroup.Requests[1].ID != createdGroup.Requests[1].ID {
		t.Fatalf("listed request member order changed: created=%+v listed=%+v", createdGroup.Requests, listedGroup.Requests)
	}

	for _, request := range listedGroup.Requests {
		if request.Path != "kv/data/payroll" || request.Operation != "create" || len(request.Data) != 0 {
			t.Fatalf("unexpected listed request member: %+v", request)
		}
	}

	approvalHeaders := map[string]string{"X-CSRF-Token": appSession.CSRFToken}
	approval := mustCallWithHeaders(t, ctx, application, "", http.MethodPost, "api/v1/request-groups/"+url.PathEscape(createdGroup.ID)+"/approve", map[string]any{}, approvalHeaders, http.StatusOK)
	var approvedGroup applicationRequestGroup
	decodeResponse(t, approval, &approvedGroup)
	if approvedGroup.Status != "approved" || len(approvedGroup.Requests) != 2 {
		t.Fatalf("application approval response was not approved: %+v", approvedGroup)
	}

	for _, request := range approvedGroup.Requests {
		if !request.Approved || request.Status != "approved" {
			t.Fatalf("application did not approve every group member: %+v", approvedGroup.Requests)
		}
	}

	for _, wrapping := range approvedWrappings {
		approved := inspectControlGroup(ctx, t, bao, serviceToken, map[string]string{"accessor": wrapping.Accessor})
		if !approved.Approved || len(approved.Authorizations) != 1 {
			t.Fatalf("expected one human authorization, got %+v", approved)
		}
	}

	mustCall(t, ctx, bao, rootToken, http.MethodGet, "kv/data/payroll", nil, http.StatusNotFound)
	mustCall(t, ctx, bao, approvedWrappings[0].Token, http.MethodPost, "sys/wrapping/unwrap", map[string]any{}, http.StatusOK, http.StatusNoContent)
	assertPayrollSecret(ctx, t, bao, "approved-first", firstMarker)
	mustCall(t, ctx, bao, approvedWrappings[1].Token, http.MethodPost, "sys/wrapping/unwrap", map[string]any{}, http.StatusOK, http.StatusNoContent)
	assertPayrollSecret(ctx, t, bao, "approved-second", secondMarker)
	t.Log("application approved an explicit ordered group through its CSRF-protected API")

	rejectedWrappings := []wrappingInfo{
		issueProtectedWrite(ctx, t, bao, alice.Auth.ClientToken, "must-not-run", "rejected-first"),
		issueProtectedWrite(ctx, t, bao, alice.Auth.ClientToken, "must-not-run", "rejected-second"),
	}
	rejectedSubmission := map[string]any{
		"idempotencyKey": "e2e-rejected-batch",
		"reason":         "Reject ordered payroll updates",
		"accessors":      []string{rejectedWrappings[0].Accessor, rejectedWrappings[1].Accessor},
	}
	rejectedResponse := mustCall(t, ctx, application, alice.Auth.ClientToken, http.MethodPost, "api/v1/request-groups", rejectedSubmission, http.StatusCreated)
	var rejectedGroup applicationRequestGroup
	decodeResponse(t, rejectedResponse, &rejectedGroup)
	if rejectedGroup.ID == "" || len(rejectedGroup.Requests) != 2 {
		t.Fatalf("unexpected rejected-group submission: %+v", rejectedGroup)
	}

	rejection := mustCallWithHeaders(t, ctx, application, "", http.MethodPost, "api/v1/request-groups/"+url.PathEscape(rejectedGroup.ID)+"/reject", map[string]any{}, approvalHeaders, http.StatusOK)
	decodeResponse(t, rejection, &rejectedGroup)
	if rejectedGroup.Status != "rejected" {
		t.Fatalf("application rejection status = %q", rejectedGroup.Status)
	}

	for _, request := range rejectedGroup.Requests {
		if request.Status != "rejected" {
			t.Fatalf("application did not reject every group member: %+v", rejectedGroup.Requests)
		}
	}

	for _, wrapping := range rejectedWrappings {
		mustCall(t, ctx, bao, serviceToken, http.MethodPost, "sys/control-group/request", map[string]string{"accessor": wrapping.Accessor}, http.StatusBadRequest, http.StatusNotFound)
	}

	assertPayrollSecret(ctx, t, bao, "approved-second", secondMarker)
	t.Log("application rejected an explicit group and revoked every wrapping accessor")

	t.Log("real OpenBao control-group workflow passed")
}

type isolatedProcessPaths struct {
	home      string
	temporary string
}

func (p isolatedProcessPaths) environment(values ...string) []string {
	environment := make([]string, 0, 3+len(values))
	environment = append(environment,
		"HOME="+p.home,
		"TMPDIR="+p.temporary,
		"XDG_CONFIG_HOME="+filepath.Join(p.home, ".config"),
	)
	return append(environment, values...)
}

type liveAPI struct {
	baseURL string
	client  *http.Client
	process *managedProcess
	port    int
}

type loginEnvelope struct {
	Auth struct {
		ClientToken      string   `json:"client_token"`
		EntityID         string   `json:"entity_id"`
		IdentityPolicies []string `json:"identity_policies"`
	} `json:"auth"`
}

type wrappingInfo struct {
	Token    string `json:"token"`
	Accessor string `json:"accessor"`
}

type applicationRequestGroup struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
	Status string `json:"status"`
	Entity struct {
		Name string `json:"name"`
	} `json:"entity"`
	Requests []struct {
		ID        string          `json:"id"`
		Position  int             `json:"position"`
		Approved  bool            `json:"approved"`
		Status    string          `json:"status"`
		Operation string          `json:"operation"`
		Path      string          `json:"path"`
		Data      json.RawMessage `json:"data"`
	} `json:"requests"`
}

type controlGroupEnvelope struct {
	Data struct {
		Approved         bool   `json:"approved"`
		RequestPath      string `json:"request_path"`
		RequestOperation string `json:"request_operation"`
		RequestData      struct {
			Data struct {
				Marker string `json:"marker"`
			} `json:"data"`
		} `json:"request_data"`
		RequestEntity struct {
			Name string `json:"name"`
		} `json:"request_entity"`
		Authorizations []json.RawMessage `json:"authorizations"`
	} `json:"data"`
}

func testRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate E2E source file")
	}

	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}

	return root
}

func requiredExecutable(t *testing.T, environmentName string) string {
	t.Helper()
	binary := os.Getenv(environmentName)
	if binary == "" {
		t.Fatalf("%s is required; run make e2e", environmentName)
	}

	absolute, err := filepath.Abs(binary)
	if err != nil {
		t.Fatalf("resolve %s: %v", environmentName, err)
	}

	info, err := os.Stat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s is not an executable regular file: %s", environmentName, absolute)
	}

	return absolute
}

func registerProcessCleanup(t *testing.T, name string, process *managedProcess) {
	t.Helper()
	t.Cleanup(func() {
		if err := process.stop(5 * time.Second); err != nil {
			t.Errorf("stop %s process group: %v", name, err)
		}

		if t.Failed() {
			t.Logf("%s log (%s):\n%s", name, process.logPath, readProcessLog(process.logPath))
		}
	})
}

func writePolicy(ctx context.Context, t *testing.T, api *liveAPI, repositoryRoot, name, fixture string) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(repositoryRoot, "e2e", "policies", fixture))
	if err != nil {
		t.Fatalf("read %s policy: %v", name, err)
	}

	mustCall(t, ctx, api, rootToken, http.MethodPut, "sys/policies/acl/"+name, map[string]string{"policy": string(contents)}, http.StatusOK, http.StatusNoContent)
}

func createEntity(ctx context.Context, t *testing.T, api *liveAPI, name string) string {
	t.Helper()
	response := mustCall(t, ctx, api, rootToken, http.MethodPost, "identity/entity", map[string]string{"name": name}, http.StatusOK)
	var envelope struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	decodeResponse(t, response, &envelope)
	if envelope.Data.ID == "" {
		t.Fatalf("create entity %s returned no ID", name)
	}

	return envelope.Data.ID
}

func createEntityAlias(ctx context.Context, t *testing.T, api *liveAPI, name, mountAccessor, entityID string) {
	t.Helper()
	mustCall(t, ctx, api, rootToken, http.MethodPost, "identity/entity-alias", map[string]string{
		"name": name, "mount_accessor": mountAccessor, "canonical_id": entityID,
	}, http.StatusOK)
}

func createIdentityGroup(ctx context.Context, t *testing.T, api *liveAPI, name, entityID, policy string) {
	t.Helper()
	mustCall(t, ctx, api, rootToken, http.MethodPost, "identity/group", map[string]any{
		"name": name, "type": "internal", "member_entity_ids": []string{entityID}, "policies": []string{policy},
	}, http.StatusOK)
}

func loginUserpass(ctx context.Context, t *testing.T, api *liveAPI, username, password string) loginEnvelope {
	t.Helper()
	response := mustCall(t, ctx, api, "", http.MethodPost, "auth/userpass/login/"+username, map[string]string{"password": password}, http.StatusOK)
	var envelope loginEnvelope
	decodeResponse(t, response, &envelope)
	if envelope.Auth.ClientToken == "" {
		t.Fatalf("%s login returned no token", username)
	}

	return envelope
}

func assertIdentityLogin(t *testing.T, name string, login loginEnvelope, entityID, policy string) {
	t.Helper()
	if login.Auth.EntityID != entityID {
		t.Fatalf("%s login entity = %q, want %q", name, login.Auth.EntityID, entityID)
	}

	if !slices.Contains(login.Auth.IdentityPolicies, policy) {
		t.Fatalf("%s identity policies = %v, want %q", name, login.Auth.IdentityPolicies, policy)
	}
}

func inspectControlGroup(ctx context.Context, t *testing.T, api *liveAPI, token string, payload map[string]string) controlGroupEnvelopeData {
	t.Helper()
	response := mustCall(t, ctx, api, token, http.MethodPost, "sys/control-group/request", payload, http.StatusOK)
	var envelope controlGroupEnvelope
	decodeResponse(t, response, &envelope)
	return envelope.Data
}

type controlGroupEnvelopeData = struct {
	Approved         bool   `json:"approved"`
	RequestPath      string `json:"request_path"`
	RequestOperation string `json:"request_operation"`
	RequestData      struct {
		Data struct {
			Marker string `json:"marker"`
		} `json:"data"`
	} `json:"request_data"`
	RequestEntity struct {
		Name string `json:"name"`
	} `json:"request_entity"`
	Authorizations []json.RawMessage `json:"authorizations"`
}

func issueProtectedWrite(ctx context.Context, t *testing.T, api *liveAPI, token, status, marker string) wrappingInfo {
	t.Helper()
	response := mustCall(t, ctx, api, token, http.MethodPost, "kv/data/payroll", map[string]any{
		"data": map[string]string{"status": status, "marker": marker},
	}, http.StatusOK)
	var envelope struct {
		WrapInfo wrappingInfo `json:"wrap_info"`
	}
	decodeResponse(t, response, &envelope)
	if envelope.WrapInfo.Token == "" || envelope.WrapInfo.Accessor == "" {
		t.Fatalf("protected write %q did not return wrapping details", marker)
	}

	return envelope.WrapInfo
}

func assertPayrollSecret(ctx context.Context, t *testing.T, api *liveAPI, status, marker string) {
	t.Helper()
	response := mustCall(t, ctx, api, rootToken, http.MethodGet, "kv/data/payroll", nil, http.StatusOK)
	var secret struct {
		Data struct {
			Data struct {
				Status string `json:"status"`
				Marker string `json:"marker"`
			} `json:"data"`
		} `json:"data"`
	}
	decodeResponse(t, response, &secret)
	if secret.Data.Data.Status != status || secret.Data.Data.Marker != marker {
		t.Fatalf("resulting secret = %+v, want status %q marker %q", secret.Data.Data, status, marker)
	}
}

func mustCall(t *testing.T, ctx context.Context, api *liveAPI, token, method, path string, payload any, expected ...int) []byte { //nolint:revive // testing.T stays first in test helpers.
	t.Helper()
	return mustCallWithHeaders(t, ctx, api, token, method, path, payload, nil, expected...)
}

func mustCallWithHeaders(t *testing.T, ctx context.Context, api *liveAPI, token, method, path string, payload any, headers map[string]string, expected ...int) []byte { //nolint:revive // testing.T stays first in test helpers.
	t.Helper()
	body, status, err := callAPI(ctx, api, token, method, path, payload, headers)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}

	if !slices.Contains(expected, status) {
		t.Fatalf("%s %s returned HTTP %d, want %v; response: %s", method, path, status, expected, body)
	}

	return body
}

func callAPI(ctx context.Context, api *liveAPI, token, method, path string, payload any, headers map[string]string) ([]byte, int, error) {
	if err := api.process.assertOwnsLoopbackPort(api.port); err != nil {
		return nil, 0, fmt.Errorf("refuse API call without listener ownership: %w", err)
	}

	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}

		body = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(api.baseURL, "/")+"/"+strings.TrimPrefix(path, "/"), body)
	if err != nil {
		return nil, 0, err
	}

	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	if token != "" {
		request.Header.Set("X-Vault-Token", token)
	}

	for name, value := range headers {
		request.Header.Set(name, value)
	}

	response, err := api.client.Do(request)
	if err != nil {
		return nil, 0, err
	}

	defer func() { _ = response.Body.Close() }()
	contents, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, 0, err
	}

	if err := api.process.assertOwnsLoopbackPort(api.port); err != nil {
		return nil, 0, fmt.Errorf("process lost listener during API call: %w", err)
	}

	return contents, response.StatusCode, nil
}

func decodeResponse(t *testing.T, contents []byte, destination any) {
	t.Helper()
	if err := json.Unmarshal(contents, destination); err != nil {
		t.Fatalf("decode JSON response: %v; response: %s", err, contents)
	}
}
