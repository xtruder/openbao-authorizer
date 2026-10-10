//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
	"github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1/authorizerv1connect"
)

const (
	rootToken        = "openbao-e2e-root"
	approverPassword = "approver-e2e-password"
	approverPolicy   = "openbao-authorizer-approver"
	authorizerPolicy = "openbao-authorizer"
	sessionPolicy    = "opencode-session"
	minterPolicy     = "opencode-minter"
	tokenRole        = "opencode-session"
	aliasPrefix      = "opencode-session-"
	ciRole           = "ci"
	selfRole         = "self-approver"
)

// Exit codes documented by bao-cred.
const (
	exitDenied  = 3
	exitPending = 4
)

func TestSessionGrantWorkflow(t *testing.T) {
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
	baoCredBinary := requiredExecutable(t, "OPENBAO_E2E_BAO_CRED_BINARY")
	bunBinary := requiredExecutable(t, "OPENBAO_E2E_BUN_BINARY")
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
	baoAddress := strings.TrimSuffix(bao.baseURL, "/v1")
	mustCall(t, ctx, bao, "", http.MethodGet, "sys/health", nil, http.StatusOK)

	// Secrets that sessions ask for, plus the OpenBao objects the plan's setup defines.
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "sys/mounts/kv", map[string]any{
		"type": "kv", "options": map[string]string{"version": "2"},
	}, http.StatusOK, http.StatusNoContent)
	for _, name := range []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "folder/nested"} {
		mustCall(t, ctx, bao, rootToken, http.MethodPost, "kv/data/e2e/"+name, map[string]any{
			"data": map[string]string{"value": "secret-" + name},
		}, http.StatusOK)
	}

	// The e2e-kv rule discovers its paths by listing kv/metadata/e2e.
	writePolicy(ctx, t, bao, authorizerPolicy, readRepositoryFile(t, repositoryRoot, "config/authorizer-policy.hcl")+
		"path \"kv/metadata/e2e\" {\n  capabilities = [\"list\"]\n}\n")
	writePolicy(ctx, t, bao, approverPolicy, readRepositoryFile(t, repositoryRoot, "config/approver-policy.hcl"))
	writePolicy(ctx, t, bao, sessionPolicy, "# Baseline Session Token policy: no access beyond default.\n")
	writePolicy(ctx, t, bao, minterPolicy, fmt.Sprintf("path \"auth/token/create/%s\" {\n  capabilities = [\"update\"]\n}\n", tokenRole))
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/token/roles/"+tokenRole, map[string]any{
		"allowed_policies": []string{sessionPolicy}, "orphan": true, "renewable": true, "token_period": "24h",
		"allowed_entity_aliases": []string{aliasPrefix + "*"},
	}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "sys/auth/approle", map[string]string{"type": "approle"}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/approle/role/opencode-minter", map[string]any{
		"token_policies": []string{minterPolicy}, "token_ttl": "15m",
	}, http.StatusOK, http.StatusNoContent)
	// AppRole logins match the "ci" Requester Rule: one role is a plain CI
	// identity, the other also holds the approver policy.
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/approle/role/"+ciRole, map[string]any{"token_ttl": "15m"}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/approle/role/"+selfRole, map[string]any{
		"token_policies": []string{approverPolicy}, "token_ttl": "15m",
	}, http.StatusOK, http.StatusNoContent)
	roleIDFile := filepath.Join(runtimeDirectory, "minter-role-id")
	secretIDFile := filepath.Join(runtimeDirectory, "minter-secret-id")
	writeSecretFile(t, roleIDFile, responseString(t, mustCall(t, ctx, bao, rootToken, http.MethodGet, "auth/approle/role/opencode-minter/role-id", nil, http.StatusOK), "role_id"))
	writeSecretFile(t, secretIDFile, responseString(t, mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/approle/role/opencode-minter/secret-id", map[string]any{}, http.StatusOK), "secret_id"))

	mustCall(t, ctx, bao, rootToken, http.MethodPost, "sys/auth/userpass", map[string]string{"type": "userpass"}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/userpass/users/approver", map[string]any{
		"password": approverPassword, "token_policies": []string{approverPolicy},
	}, http.StatusOK, http.StatusNoContent)
	authorizerToken := createToken(ctx, t, bao, map[string]any{"policies": []string{authorizerPolicy}, "no_default_policy": true, "ttl": "1h"})
	authorizerTokenFile := filepath.Join(runtimeDirectory, "authorizer-token")
	writeSecretFile(t, authorizerTokenFile, authorizerToken)

	encryptionKey := make([]byte, 32)
	if _, randomErr := rand.Read(encryptionKey); randomErr != nil {
		t.Fatalf("generate application encryption key: %v", randomErr)
	}

	encryptionKeyFile := filepath.Join(runtimeDirectory, "encryption-key")
	writeSecretFile(t, encryptionKeyFile, base64.StdEncoding.EncodeToString(encryptionKey))
	staticDirectory := filepath.Join(runtimeDirectory, "static")
	if mkdirErr := os.Mkdir(staticDirectory, 0o755); mkdirErr != nil {
		t.Fatalf("create static directory: %v", mkdirErr)
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
  address               = %q
  authorizer_token_file = %q
  approver_policy       = %q
}
approver_login {
  openbao_address = %q
  method "token" {}
  method "userpass" {}
}
requester "opencode" {
  token_role = %q
}
requester "ci" {
  auth_mount = "approle"
}
grants {
  default_ttl = "1h"
  pending_ttl = "10m"
}
grantable "e2e-kv" {
  path         = "kv/data/e2e/*"
  capabilities = ["read"]
  max_ttl      = "2h"
  description  = "E2E secrets"
  discover     = "kv/metadata/e2e"
}
`, staticDirectory, filepath.Join(runtimeDirectory, "app.db"), encryptionKeyFile, baoAddress, authorizerTokenFile, approverPolicy, baoAddress, tokenRole)
	writeSecretFile(t, appConfig, configuration)

	appLog := filepath.Join(runtimeDirectory, "app.log")
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

	application := &liveAPI{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", appPort),
		client:  &http.Client{Timeout: 15 * time.Second},
		process: appProcess,
		port:    appPort,
	}
	mustCall(t, ctx, application, "", http.MethodGet, "healthz", nil, http.StatusOK)

	// The PWA calls OpenBao directly, so OpenBao must allow its origin.
	mustCall(t, ctx, bao, rootToken, http.MethodPut, "sys/config/cors", map[string]any{
		"enabled": true, "allowed_origins": []string{application.baseURL},
		"allowed_headers": []string{"X-Vault-Token", "X-Vault-Namespace", "X-Vault-Request", "Content-Type"},
	}, http.StatusOK, http.StatusNoContent)
	if allowed := corsPreflight(ctx, t, bao, "auth/userpass/login/approver", application.baseURL); allowed != application.baseURL {
		t.Fatalf("OpenBao CORS preflight allowed origin %q, want %q", allowed, application.baseURL)
	}

	options, err := newApproverRPC(application).GetLoginOptions(ctx, connect.NewRequest(&authorizerv1.GetLoginOptionsRequest{}))
	if err != nil || options.Msg.GetOpenbaoAddress() != baoAddress || len(options.Msg.GetMethods()) != 2 || options.Msg.GetMethods()[1].GetMount() != "userpass" {
		t.Fatalf("login options = %v, %v", options, err)
	}

	// The approver signs in to OpenBao itself, as the PWA does, and hands
	// the token over once; the authorizer revokes it.
	approverToken := responseAuthToken(t, mustCall(t, ctx, bao, "", http.MethodPost, "auth/userpass/login/approver", map[string]string{"password": approverPassword}, http.StatusOK))
	approver := newApproverClient(ctx, t, application, approverToken)
	mustCall(t, ctx, bao, approverToken, http.MethodGet, "auth/token/lookup-self", nil, http.StatusForbidden)
	t.Log("OpenBao allows the PWA origin; the approver's userpass token became an app session and was revoked")

	mint := sessionMinter{
		bun:     bunBinary,
		cli:     filepath.Join(repositoryRoot, "integrations", "opencode", "src", "mint-cli.ts"),
		root:    repositoryRoot,
		paths:   processPaths,
		address: baoAddress,
		roleID:  roleIDFile,
		secret:  secretIDFile,
	}
	sessionA := mint.mint(ctx, t, "e2e-session-a", "E2E session A")
	cred := baoCred{binary: baoCredBinary, paths: processPaths, address: baoAddress, authorizer: application.baseURL}

	if sessionA.EntityAlias != aliasPrefix+"e2e-session-a" || sessionA.EntityID == "" {
		t.Fatalf("minted session A = %+v", sessionA)
	}

	assertRead(ctx, t, bao, sessionA.Token, "alpha", http.StatusForbidden)
	t.Log("session A minted through the plugin's mint CLI; its baseline token cannot read kv/data/e2e/alpha")

	// A batch where the approver approves one item and rejects another, and the
	// authorizer refuses two before anyone sees them.
	batch := cred.start(ctx, sessionA.Token,
		"request", "--reason", "e2e: deploy needs alpha and beta",
		"--item", "kv/data/e2e/alpha=read",
		"--item", "kv/data/e2e/beta=read",
		"--item", "kv/data/outside/rules=read",
		"--item", "sys/policies/acl/agent-grant-x=read",
		"--timeout", "2m",
	)
	pending := approver.waitForPending(ctx, t, "kv/data/e2e/alpha", "kv/data/e2e/beta")
	if requester := pending.GetRequester(); pending.GetReason() != "e2e: deploy needs alpha and beta" || requester.GetId() != "e2e-session-a" || requester.GetTitle() != "E2E session A" || requester.GetRule() != "opencode" {
		t.Fatalf("approver view of the request = %+v", pending)
	}

	approver.decide(ctx, t, pending, map[string]authorizerv1.Decision{"kv/data/e2e/alpha": authorizerv1.Decision_DECISION_APPROVE, "kv/data/e2e/beta": authorizerv1.Decision_DECISION_REJECT}, nil)
	result := batch.wait(t)
	if result.exitCode != exitDenied {
		t.Fatalf("bao-cred request exit = %d, want %d\nstdout: %s\nstderr: %s", result.exitCode, exitDenied, result.stdout, result.stderr)
	}

	states := itemStates(t, result.stdout)
	want := map[string]string{
		"kv/data/e2e/alpha":              "approved",
		"kv/data/e2e/beta":               "rejected",
		"kv/data/outside/rules":          "refused",
		"sys/policies/acl/agent-grant-x": "refused",
	}
	for path, state := range want {
		if states[path] != state {
			t.Fatalf("item states = %v, want %v", states, want)
		}
	}

	assertRead(ctx, t, bao, sessionA.Token, "alpha", http.StatusOK)
	assertRead(ctx, t, bao, sessionA.Token, "beta", http.StatusForbidden)
	read := cred.run(ctx, t, sessionA.Token, "read", "--field", "data.value", "kv/data/e2e/alpha")
	if read.exitCode != 0 || read.stdout != "secret-alpha" {
		t.Fatalf("bao-cred read = %+v", read)
	}

	var entity struct {
		Data struct {
			Policies []string `json:"policies"`
		} `json:"data"`
	}
	decodeResponse(t, mustCall(t, ctx, bao, rootToken, http.MethodGet, "identity/entity/id/"+sessionA.EntityID, nil, http.StatusOK), &entity)
	grantPolicies := slices.DeleteFunc(entity.Data.Policies, func(name string) bool { return !strings.HasPrefix(name, "agent-grant-") })
	if len(grantPolicies) != 1 {
		t.Fatalf("session A entity policies = %v, want exactly one agent-grant- policy", entity.Data.Policies)
	}

	t.Log("approved item works for session A's existing token through its one session policy; rejected and refused items do not")

	// Asking again for something OpenBao already allows needs no approver.
	repeat := cred.run(ctx, t, sessionA.Token, "request", "--reason", "e2e: again", "--item", "kv/data/e2e/alpha=read", "--timeout", "30s")
	if repeat.exitCode != 0 || itemStates(t, repeat.stdout)["kv/data/e2e/alpha"] != "already_granted" {
		t.Fatalf("repeated request = %+v", repeat)
	}

	if requests := approver.list(ctx, t, authorizerv1.GrantRequestFilter_GRANT_REQUEST_FILTER_PENDING); len(requests) != 0 {
		t.Fatalf("already granted item reached approvers: %+v", requests)
	}

	// A request filed without waiting can be resumed by its ID.
	filed := cred.run(ctx, t, sessionA.Token, "request", "--reason", "e2e: gamma", "--item", "kv/data/e2e/gamma=read", "--no-wait")
	if filed.exitCode != exitPending {
		t.Fatalf("no-wait request = %+v", filed)
	}

	gamma := approver.waitForPending(ctx, t, "kv/data/e2e/gamma")
	approver.decide(ctx, t, gamma, map[string]authorizerv1.Decision{"kv/data/e2e/gamma": authorizerv1.Decision_DECISION_APPROVE}, nil)
	resumed := cred.run(ctx, t, sessionA.Token, "request", "--wait", requestID(t, filed.stdout), "--timeout", "30s")
	if resumed.exitCode != 0 || itemStates(t, resumed.stdout)["kv/data/e2e/gamma"] != "approved" {
		t.Fatalf("resumed wait = %+v", resumed)
	}

	assertRead(ctx, t, bao, sessionA.Token, "gamma", http.StatusOK)
	t.Log("already-granted items skip approval; a request filed with --no-wait resumes with --wait")

	// Grants belong to the session, not to other sessions; subagents share their root's grants.
	sessionB := mint.mint(ctx, t, "e2e-session-b", "E2E session B")
	if sessionB.EntityID == sessionA.EntityID {
		t.Fatal("sessions A and B share an entity")
	}

	assertRead(ctx, t, bao, sessionB.Token, "alpha", http.StatusForbidden)
	child := mint.mint(ctx, t, "e2e-subagent", "", "e2e-session-a")
	if child.RootSessionID != "e2e-session-a" || child.EntityID != sessionA.EntityID || child.Token == sessionA.Token {
		t.Fatalf("subagent token = %+v", child)
	}

	assertRead(ctx, t, bao, child.Token, "alpha", http.StatusOK)
	t.Log("session B cannot use A's grant; a subagent of A can")

	// A short-lived Grant's block lapses through OpenBao's own expiration while
	// the other blocks of the session policy keep working.
	short := cred.start(ctx, sessionA.Token, "request", "--reason", "e2e: brief delta", "--item", "kv/data/e2e/delta=read", "--ttl", "5s", "--timeout", "2m")
	delta := approver.waitForPending(ctx, t, "kv/data/e2e/delta")
	approver.decide(ctx, t, delta, map[string]authorizerv1.Decision{"kv/data/e2e/delta": authorizerv1.Decision_DECISION_APPROVE}, nil)
	if result := short.wait(t); result.exitCode != 0 {
		t.Fatalf("short grant request = %+v", result)
	}

	assertRead(ctx, t, bao, sessionA.Token, "delta", http.StatusOK)
	waitForRead(ctx, t, bao, sessionA.Token, "delta", http.StatusForbidden, 20*time.Second)
	assertRead(ctx, t, bao, sessionA.Token, "alpha", http.StatusOK)
	t.Log("a 5s Grant stopped working after it expired; alpha still works")

	// Revoking a Grant takes effect immediately.
	grantID := approver.activeGrant(ctx, t, "e2e-session-a", "kv/data/e2e/gamma")
	if _, revokeErr := approver.rpc.RevokeGrant(ctx, connect.NewRequest(&authorizerv1.RevokeGrantRequest{GrantId: grantID})); revokeErr != nil {
		t.Fatalf("revoke Grant: %v", revokeErr)
	}

	assertRead(ctx, t, bao, sessionA.Token, "gamma", http.StatusForbidden)
	assertRead(ctx, t, bao, sessionA.Token, "alpha", http.StatusOK)
	t.Log("revoking one Grant removed only that access")

	// A read with --reason files a request on permission denied and retries after approval.
	autoRead := cred.start(ctx, sessionA.Token, "read", "--reason", "e2e: read epsilon", "--field", "data.value", "--timeout", "2m", "kv/data/e2e/epsilon")
	epsilon := approver.waitForPending(ctx, t, "kv/data/e2e/epsilon")
	approver.decide(ctx, t, epsilon, map[string]authorizerv1.Decision{"kv/data/e2e/epsilon": authorizerv1.Decision_DECISION_APPROVE}, nil)
	if result := autoRead.wait(t); result.exitCode != 0 || result.stdout != "secret-epsilon" {
		t.Fatalf("auto-requesting read = %+v", result)
	}

	withoutReason := cred.run(ctx, t, sessionB.Token, "read", "kv/data/e2e/epsilon")
	if withoutReason.exitCode != 1 || !strings.Contains(withoutReason.stderr, "--reason") {
		t.Fatalf("denied read without --reason = %+v", withoutReason)
	}

	grants := cred.run(ctx, t, sessionA.Token, "grants")
	if grants.exitCode != 0 || !strings.Contains(grants.stdout, "kv/data/e2e/alpha") || !strings.Contains(grants.stdout, "kv/data/e2e/epsilon") || strings.Contains(grants.stdout, "kv/data/e2e/gamma") {
		t.Fatalf("bao-cred grants = %+v", grants)
	}

	t.Log("bao-cred read --reason requested access on denial and read the secret after approval")

	// A Requester finds a concrete path in the catalog and requests it.
	catalog := cred.run(ctx, t, sessionB.Token, "grantable")
	var grantables []struct {
		Name          string   `json:"name"`
		Path          string   `json:"path"`
		MaxTTL        string   `json:"max_ttl"`
		Description   string   `json:"description"`
		Paths         []string `json:"paths"`
		DiscoverError string   `json:"discover_error"`
	}
	if catalog.exitCode != 0 || json.Unmarshal([]byte(catalog.stdout), &grantables) != nil || len(grantables) != 1 {
		t.Fatalf("bao-cred grantable = %+v", catalog)
	}

	if rule := grantables[0]; rule.Name != "e2e-kv" || rule.Path != "kv/data/e2e/*" || rule.MaxTTL != "2h0m0s" || rule.Description != "E2E secrets" ||
		rule.DiscoverError != "" || !slices.Contains(rule.Paths, "kv/data/e2e/theta") || slices.Contains(rule.Paths, "kv/data/e2e/folder/") {
		t.Fatalf("e2e-kv grantable = %+v", rule)
	}

	theta := cred.start(ctx, sessionB.Token, "read", "--reason", "e2e: theta from the catalog", "--field", "data.value", "--timeout", "2m", "kv/data/e2e/theta")
	thetaRequest := approver.waitForPending(ctx, t, "kv/data/e2e/theta")
	approver.decide(ctx, t, thetaRequest, map[string]authorizerv1.Decision{"kv/data/e2e/theta": authorizerv1.Decision_DECISION_APPROVE}, nil)
	if result := theta.wait(t); result.exitCode != 0 || result.stdout != "secret-theta" {
		t.Fatalf("read of a discovered path = %+v", result)
	}

	t.Log("bao-cred grantable listed kv/data/e2e/theta from kv/metadata/e2e; reading it with --reason worked after approval")

	// Only tokens matching a Requester Rule may request Grants.
	humanToken := responseAuthToken(t, mustCall(t, ctx, bao, "", http.MethodPost, "auth/userpass/login/approver", map[string]string{"password": approverPassword}, http.StatusOK))
	grantAPI := authorizerv1connect.NewGrantServiceClient(application.rpcHTTPClient(), application.baseURL+"/api")
	if _, err = grantAPI.CreateGrantRequest(ctx, grantRequest(humanToken, "human", "kv/data/e2e/alpha")); errorReason(err) != "NOT_REQUESTER" {
		t.Fatalf("approver token on the Grant API: %v, want NOT_REQUESTER", err)
	}

	// An AppRole login matches the "ci" Requester Rule and gets its own Grant.
	ciToken := appRoleLogin(ctx, t, bao, ciRole)
	if _, err = grantAPI.CreateGrantRequest(ctx, grantRequest(ciToken, "e2e: ci needs zeta", "kv/data/e2e/zeta")); err != nil {
		t.Fatalf("AppRole grant request: %v", err)
	}

	zeta := approver.waitForPending(ctx, t, "kv/data/e2e/zeta")
	if rule := zeta.GetRequester().GetRule(); rule != "ci" {
		t.Fatalf("AppRole request matched rule %q, want ci", rule)
	}

	approver.decide(ctx, t, zeta, map[string]authorizerv1.Decision{"kv/data/e2e/zeta": authorizerv1.Decision_DECISION_APPROVE}, nil)
	assertRead(ctx, t, bao, ciToken, "zeta", http.StatusOK)
	assertRead(ctx, t, bao, sessionA.Token, "zeta", http.StatusForbidden)

	// An identity that is both Requester and Approver can't decide its own request.
	selfToken := appRoleLogin(ctx, t, bao, selfRole)
	selfRequest, err := grantAPI.CreateGrantRequest(ctx, grantRequest(selfToken, "e2e: self", "kv/data/e2e/eta"))
	if err != nil {
		t.Fatalf("self-approver grant request: %v", err)
	}

	selfApprover := newApproverClient(ctx, t, application, selfToken)
	item := selfRequest.Msg.GetGrantRequest().GetItems()[0]
	_, err = selfApprover.rpc.DecideItems(ctx, connect.NewRequest(&authorizerv1.DecideItemsRequest{
		GrantRequestId: selfRequest.Msg.GetGrantRequest().GetId(),
		Decisions:      []*authorizerv1.ItemDecision{{ItemId: item.GetId(), Decision: authorizerv1.Decision_DECISION_APPROVE}},
	}))
	if errorReason(err) != "SELF_APPROVAL" {
		t.Fatalf("self-approval: %v, want SELF_APPROVAL", err)
	}

	t.Log("approver tokens are refused by the Grant API; an AppRole Requester got a Grant; self-approval is refused")

	// The authorizer token can change nothing on an entity except its policies.

	mustCall(t, ctx, bao, authorizerToken, http.MethodPost, "identity/entity/id/"+sessionA.EntityID, map[string]any{"name": "renamed"}, http.StatusForbidden)
	mustCall(t, ctx, bao, authorizerToken, http.MethodPost, "identity/entity/id/"+sessionA.EntityID, map[string]any{"disabled": true}, http.StatusForbidden)
	mustCall(t, ctx, bao, authorizerToken, http.MethodPost, "sys/policies/acl/not-a-grant", map[string]string{"policy": "path \"kv/*\" { capabilities = [\"read\"] }"}, http.StatusForbidden)
	t.Log("the authorizer token cannot rename or disable entities or write other policies")

	t.Log("real OpenBao session-grant workflow passed")
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

type mintedSession struct {
	SessionID     string `json:"session_id"`
	RootSessionID string `json:"root_session_id"`
	EntityAlias   string `json:"entity_alias"`
	Token         string `json:"token"`
	EntityID      string `json:"entity_id"`
}

// sessionMinter runs the opencode plugin's mint CLI, so the E2E exercises the
// same minting code the plugin uses.
type sessionMinter struct {
	bun     string
	cli     string
	root    string
	paths   isolatedProcessPaths
	address string
	roleID  string
	secret  string
}

func (m sessionMinter) mint(ctx context.Context, t *testing.T, sessionID, title string, parents ...string) mintedSession {
	t.Helper()
	arguments := []string{m.cli, "--session-id", sessionID, "--address", m.address, "--role-id-file", m.roleID, "--secret-id-file", m.secret, "--directory", m.root}
	if title != "" {
		arguments = append(arguments, "--title", title)
	}

	for _, parent := range parents {
		arguments = append(arguments, "--parent", parent)
	}

	result := runProcess(ctx, m.paths.environment(), m.bun, arguments...)
	if result.exitCode != 0 {
		t.Fatalf("mint session %s: exit %d: %s", sessionID, result.exitCode, result.stderr)
	}

	var session mintedSession
	decodeResponse(t, []byte(result.stdout), &session)
	if session.Token == "" {
		t.Fatalf("mint session %s returned no token", sessionID)
	}

	return session
}

type baoCred struct {
	binary     string
	paths      isolatedProcessPaths
	address    string
	authorizer string
}

func (c baoCred) environment(token string) []string {
	return c.paths.environment("BAO_ADDR="+c.address, "BAO_TOKEN="+token, "BAO_AUTHORIZER_ADDR="+c.authorizer)
}

func (c baoCred) run(ctx context.Context, t *testing.T, token string, arguments ...string) processResult {
	t.Helper()
	return runProcess(ctx, c.environment(token), c.binary, arguments...)
}

func (c baoCred) start(ctx context.Context, token string, arguments ...string) *backgroundProcess {
	done := make(chan processResult, 1)
	go func() { done <- runProcess(ctx, c.environment(token), c.binary, arguments...) }()
	return &backgroundProcess{done: done}
}

type processResult struct {
	stdout   string
	stderr   string
	exitCode int
}

type backgroundProcess struct {
	done chan processResult
}

func (p *backgroundProcess) wait(t *testing.T) processResult {
	t.Helper()
	select {
	case result := <-p.done:
		return result
	case <-time.After(3 * time.Minute):
		t.Fatal("background process did not finish")
		return processResult{}
	}
}

func runProcess(ctx context.Context, environment []string, binary string, arguments ...string) processResult {
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	result := processResult{stdout: stdout.String(), stderr: stderr.String()}
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		result.exitCode = exitErr.ExitCode()
	} else if err != nil {
		result.exitCode = -1
		result.stderr += err.Error()
	}

	return result
}

// approverClient drives the Approver API through the generated Connect client,
// as the PWA does: a same-origin cookie session.
type approverClient struct {
	rpc authorizerv1connect.ApproverServiceClient
}

// newApproverRPC returns an Approver API client with its own cookie jar, so
// each client is a separate browser session.
func newApproverRPC(application *liveAPI) authorizerv1connect.ApproverServiceClient {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Transport: ownedTransport{api: application}}
	return authorizerv1connect.NewApproverServiceClient(client, application.baseURL+"/api")
}

// newApproverClient exchanges an OpenBao token for an app session.
func newApproverClient(ctx context.Context, t *testing.T, application *liveAPI, openBaoToken string) *approverClient {
	t.Helper()
	client := &approverClient{rpc: newApproverRPC(application)}
	if _, err := client.rpc.CreateSession(ctx, connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: openBaoToken})); err != nil {
		t.Fatalf("approver session: %v", err)
	}

	return client
}

func grantRequest(token, reason, path string) *connect.Request[authorizerv1.CreateGrantRequestRequest] {
	request := connect.NewRequest(&authorizerv1.CreateGrantRequestRequest{
		Reason: reason, Items: []*authorizerv1.PermissionItemInput{{Path: path, Capabilities: []string{"read"}}},
	})
	request.Header().Set("Authorization", "Bearer "+token)
	return request
}

// errorReason returns the ErrorDetail reason of an RPC error.
func errorReason(err error) string {
	connectErr, ok := errors.AsType[*connect.Error](err)
	if !ok {
		return ""
	}

	for _, detail := range connectErr.Details() {
		if value, valueErr := detail.Value(); valueErr == nil {
			if errorDetail, ok := value.(*authorizerv1.ErrorDetail); ok {
				return errorDetail.GetReason()
			}
		}
	}

	return ""
}

func appRoleLogin(ctx context.Context, t *testing.T, bao *liveAPI, role string) string {
	t.Helper()
	roleID := responseString(t, mustCall(t, ctx, bao, rootToken, http.MethodGet, "auth/approle/role/"+role+"/role-id", nil, http.StatusOK), "role_id")
	secretID := responseString(t, mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/approle/role/"+role+"/secret-id", map[string]any{}, http.StatusOK), "secret_id")
	return responseAuthToken(t, mustCall(t, ctx, bao, "", http.MethodPost, "auth/approle/login", map[string]string{"role_id": roleID, "secret_id": secretID}, http.StatusOK))
}

func (a *approverClient) list(ctx context.Context, t *testing.T, filter authorizerv1.GrantRequestFilter) []*authorizerv1.GrantRequest {
	t.Helper()
	response, err := a.rpc.ListGrantRequests(ctx, connect.NewRequest(&authorizerv1.ListGrantRequestsRequest{Filter: filter}))
	if err != nil {
		t.Fatalf("list Grant Requests: %v", err)
	}

	return response.Msg.GetGrantRequests()
}

// waitForPending reads the WatchEvents stream until a pending request holds
// every given path, so the E2E covers the push path the PWA relies on.
func (a *approverClient) waitForPending(ctx context.Context, t *testing.T, paths ...string) *authorizerv1.GrantRequest {
	t.Helper()
	watchContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stream, err := a.rpc.WatchEvents(watchContext, connect.NewRequest(&authorizerv1.WatchEventsRequest{}))
	if err != nil {
		t.Fatalf("watch approver events: %v", err)
	}

	defer func() { _ = stream.Close() }()
	for stream.Receive() {
		for _, request := range stream.Msg().GetSnapshot().GetPendingRequests() {
			pending := map[string]bool{}
			for _, item := range request.GetItems() {
				pending[item.GetPath()] = item.GetState() == authorizerv1.ItemState_ITEM_STATE_PENDING
			}

			if !slices.ContainsFunc(paths, func(path string) bool { return !pending[path] }) {
				return request
			}
		}
	}

	t.Fatalf("no pending request for %v on the event stream: %v", paths, stream.Err())
	return nil
}

func (a *approverClient) decide(ctx context.Context, t *testing.T, request *authorizerv1.GrantRequest, decisions map[string]authorizerv1.Decision, ttls map[string]time.Duration) {
	t.Helper()
	items := make([]*authorizerv1.ItemDecision, 0, len(decisions))
	for _, item := range request.GetItems() {
		decision, ok := decisions[item.GetPath()]
		if !ok || item.GetState() != authorizerv1.ItemState_ITEM_STATE_PENDING {
			continue
		}

		entry := &authorizerv1.ItemDecision{ItemId: item.GetId(), Decision: decision}
		if ttl, ok := ttls[item.GetPath()]; ok {
			entry.Ttl = durationpb.New(ttl)
		}

		items = append(items, entry)
	}

	if _, err := a.rpc.DecideItems(ctx, connect.NewRequest(&authorizerv1.DecideItemsRequest{GrantRequestId: request.GetId(), Decisions: items})); err != nil {
		t.Fatalf("decide items: %v", err)
	}
}

func (a *approverClient) activeGrant(ctx context.Context, t *testing.T, sessionID, path string) string {
	t.Helper()
	response, err := a.rpc.ListGrants(ctx, connect.NewRequest(&authorizerv1.ListGrantsRequest{}))
	if err != nil {
		t.Fatalf("list Grants: %v", err)
	}

	for _, grant := range response.Msg.GetGrants() {
		if grant.GetPath() == path && grant.GetRequester().GetId() == sessionID {
			return grant.GetId()
		}
	}

	t.Fatalf("no active Grant for %s in session %s: %v", path, sessionID, response.Msg.GetGrants())
	return ""
}

// rpcHTTPClient checks listener ownership around every RPC, like callAPI does.
func (api *liveAPI) rpcHTTPClient() *http.Client {
	return &http.Client{Transport: ownedTransport{api: api}}
}

type ownedTransport struct {
	api *liveAPI
}

func (o ownedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := o.api.process.assertOwnsLoopbackPort(o.api.port); err != nil {
		return nil, fmt.Errorf("refuse RPC without listener ownership: %w", err)
	}

	return http.DefaultTransport.RoundTrip(request)
}

type requestOutput struct {
	ID    string `json:"id"`
	Items []struct {
		Path  string `json:"path"`
		State string `json:"state"`
	} `json:"items"`
}

func parseRequestOutput(t *testing.T, stdout string) requestOutput {
	t.Helper()
	var output requestOutput
	decodeResponse(t, []byte(stdout), &output)
	return output
}

func itemStates(t *testing.T, stdout string) map[string]string {
	t.Helper()
	states := map[string]string{}
	for _, item := range parseRequestOutput(t, stdout).Items {
		states[item.Path] = item.State
	}

	return states
}

func requestID(t *testing.T, stdout string) string {
	t.Helper()
	id := parseRequestOutput(t, stdout).ID
	if id == "" {
		t.Fatalf("bao-cred output has no request id: %s", stdout)
	}

	return id
}

func assertRead(ctx context.Context, t *testing.T, api *liveAPI, token, name string, expected int) {
	t.Helper()
	mustCall(t, ctx, api, token, http.MethodGet, "kv/data/e2e/"+name, nil, expected)
}

func waitForRead(ctx context.Context, t *testing.T, api *liveAPI, token, name string, expected int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, status, err := callAPI(ctx, api, token, http.MethodGet, "kv/data/e2e/"+name, nil, nil); err == nil && status == expected {
			return
		}

		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("reading kv/data/e2e/%s did not return HTTP %d within %s", name, expected, timeout)
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

func readRepositoryFile(t *testing.T, repositoryRoot, path string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(repositoryRoot, path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(contents)
}

func writeSecretFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writePolicy(ctx context.Context, t *testing.T, api *liveAPI, name, policy string) {
	t.Helper()
	mustCall(t, ctx, api, rootToken, http.MethodPut, "sys/policies/acl/"+name, map[string]string{"policy": policy}, http.StatusOK, http.StatusNoContent)
}

func createToken(ctx context.Context, t *testing.T, api *liveAPI, payload map[string]any) string {
	t.Helper()
	return responseAuthToken(t, mustCall(t, ctx, api, rootToken, http.MethodPost, "auth/token/create-orphan", payload, http.StatusOK))
}

func responseAuthToken(t *testing.T, contents []byte) string {
	t.Helper()
	var envelope struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	decodeResponse(t, contents, &envelope)
	if envelope.Auth.ClientToken == "" {
		t.Fatalf("response has no client token: %s", contents)
	}

	return envelope.Auth.ClientToken
}

func responseString(t *testing.T, contents []byte, field string) string {
	t.Helper()
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	decodeResponse(t, contents, &envelope)
	value, _ := envelope.Data[field].(string)
	if value == "" {
		t.Fatalf("response has no %s", field)
	}

	return value
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

// corsPreflight sends the preflight a browser on origin sends before a JSON
// POST to path, and returns the origin OpenBao allows.
func corsPreflight(ctx context.Context, t *testing.T, api *liveAPI, path, origin string) string {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodOptions, api.baseURL+"/"+path, nil)
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Origin", origin)
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "content-type,x-vault-request")
	response, err := api.rpcHTTPClient().Do(request)
	if err != nil {
		t.Fatalf("CORS preflight: %v", err)
	}

	_ = response.Body.Close()
	return response.Header.Get("Access-Control-Allow-Origin")
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
