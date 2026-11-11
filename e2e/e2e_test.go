//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/durationpb"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
	"github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1/authorizerv1connect"
)

const (
	rootToken        = "openbao-e2e-root"
	approverPassword = "approver-e2e-password"
	approverPolicy   = "openbao-authorizer-approver"
	authorizerPolicy = "openbao-authorizer"
	identityPolicy   = "named-identity"
	minterPolicy     = "named-identity-minter"
	tokenRole        = "named-identity"
	sessionRole      = "agent-session"
	developerPass    = "dev-e2e-password"
	ciRole           = "ci"
	selfRole         = "self-approver"
)

// Exit codes documented by bao-cred.
const (
	exitDenied  = 3
	exitPending = 4
)

func TestNamedIdentityGrantWorkflow(t *testing.T) {
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

	// Secrets that Named Identities ask for, plus the OpenBao objects the plan's setup defines.
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "sys/mounts/kv", map[string]any{
		"type": "kv", "options": map[string]string{"version": "2"},
	}, http.StatusOK, http.StatusNoContent)
	for _, name := range []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa", "folder/nested"} {
		mustCall(t, ctx, bao, rootToken, http.MethodPost, "kv/data/e2e/"+name, map[string]any{
			"data": map[string]string{"value": "secret-" + name},
		}, http.StatusOK)
	}

	// An SSH CA whose e2e-node role signs only the core@e2e-node principal,
	// as a homelab role per node and user does.
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "sys/mounts/ssh", map[string]string{"type": "ssh"}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "ssh/config/ca", map[string]any{"generate_signing_key": true}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "ssh/roles/e2e-node", map[string]any{
		"key_type": "ca", "allow_user_certificates": true, "allowed_users": "core@e2e-node", "default_user": "core@e2e-node",
		"ttl": "5m", "max_ttl": "10m", "allowed_extensions": "permit-pty", "default_extensions": map[string]string{"permit-pty": ""},
		"key_id_format": "{{role_name}}-{{token_display_name}}",
	}, http.StatusOK, http.StatusNoContent)

	// The e2e-kv rule discovers its paths by listing kv/metadata/e2e.
	writePolicy(ctx, t, bao, authorizerPolicy, readRepositoryFile(t, repositoryRoot, "config/authorizer-policy.hcl")+
		"path \"kv/metadata/e2e\" {\n  capabilities = [\"list\"]\n}\n")
	writePolicy(ctx, t, bao, approverPolicy, readRepositoryFile(t, repositoryRoot, "config/approver-policy.hcl"))
	writePolicy(ctx, t, bao, identityPolicy, readRepositoryFile(t, repositoryRoot, "deploy/local/named-identity-policy.hcl"))
	writePolicy(ctx, t, bao, minterPolicy, readRepositoryFile(t, repositoryRoot, "deploy/local/named-identity-minter-policy.hcl"))
	writePolicy(ctx, t, bao, sessionRole, readRepositoryFile(t, repositoryRoot, "deploy/local/agent-session-policy.hcl"))
	// The same role settings as deploy/local/bootstrap-openbao.sh. Tokens may
	// carry the project and global Grant policies before those exist.
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/token/roles/"+tokenRole, map[string]any{
		"allowed_policies": []string{identityPolicy, "agent-grant-global"}, "allowed_policies_glob": []string{"agent-grant-project-*"},
		"orphan": true, "renewable": true, "token_period": "768h", "allowed_entity_aliases": []string{"*"},
	}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/token/roles/"+sessionRole, map[string]any{
		"allowed_policies": []string{sessionRole, "agent-grant-global"}, "allowed_policies_glob": []string{"agent-grant-project-*"},
		"orphan": false, "renewable": true, "token_period": "24h", "allowed_entity_aliases": []string{"*"},
	}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "sys/auth/approle", map[string]string{"type": "approle"}, http.StatusOK, http.StatusNoContent)
	// AppRole logins match the "ci" Requester Rule: one role is a plain CI
	// identity, the other also holds the approver policy.
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/approle/role/"+ciRole, map[string]any{"token_ttl": "15m"}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/approle/role/"+selfRole, map[string]any{
		"token_policies": []string{approverPolicy}, "token_ttl": "15m",
	}, http.StatusOK, http.StatusNoContent)

	mustCall(t, ctx, bao, rootToken, http.MethodPost, "sys/auth/userpass", map[string]string{"type": "userpass"}, http.StatusOK, http.StatusNoContent)
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/userpass/users/approver", map[string]any{
		"password": approverPassword, "token_policies": []string{approverPolicy},
	}, http.StatusOK, http.StatusNoContent)
	// The developer mints Named Tokens with their own login token.
	mustCall(t, ctx, bao, rootToken, http.MethodPost, "auth/userpass/users/dev", map[string]any{
		"password": developerPass, "token_policies": []string{minterPolicy},
	}, http.StatusOK, http.StatusNoContent)
	authorizerToken := createToken(ctx, t, bao, map[string]any{"policies": []string{authorizerPolicy}, "no_default_policy": true, "period": "720h"})
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
requester "named" {
  token_role = %q
}
requester "sessions" {
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
grantable "e2e-ssh" {
  path         = "ssh/sign/*"
  capabilities = ["update"]
  max_ttl      = "1h"
  description  = "SSH certificates"
}
`, staticDirectory, filepath.Join(runtimeDirectory, "app.db"), encryptionKeyFile, baoAddress, authorizerTokenFile, approverPolicy, baoAddress, tokenRole, sessionRole)
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

	// The authorizer renews its periodic token at start, through the
	// renew-self stanza of the real authorizer policy.
	if logs := readProcessLog(appLog); !strings.Contains(logs, "renewed authorizer token") || strings.Contains(logs, "renew authorizer token;") {
		t.Fatalf("authorizer token renewal not logged:\n%s", logs)
	}

	t.Log("the authorizer renewed its own periodic token at start")

	// The developer logs in as `bao login` would, writing ~/.vault-token
	// into the isolated HOME that bao-cred auth reads.
	developerToken := responseAuthToken(t, mustCall(t, ctx, bao, "", http.MethodPost, "auth/userpass/login/dev", map[string]string{"password": developerPass}, http.StatusOK))
	writeSecretFile(t, filepath.Join(isolatedHome, ".vault-token"), developerToken)
	cred := baoCred{binary: baoCredBinary, paths: processPaths, address: baoAddress, authorizer: application.baseURL}
	identityA := cred.auth(ctx, t, "e2e-project-a")
	if identityA.EntityID == "" || identityA.Store != "file" || identityA.TTL < 700*time.Hour {
		t.Fatalf("Named Identity A = %+v", identityA)
	}

	assertRead(ctx, t, bao, identityA.Token, "alpha", http.StatusForbidden)
	t.Log("bao-cred auth minted a 32-day Named Token for e2e-project-a into the file store; it cannot read kv/data/e2e/alpha")

	// A batch where the approver approves one item and rejects another, and the
	// authorizer refuses two before anyone sees them.
	batch := cred.start(ctx, identityA.env(),
		"request", "--reason", "e2e: deploy needs alpha and beta",
		"--item", "kv/data/e2e/alpha=read",
		"--item", "kv/data/e2e/beta=read",
		"--item", "kv/data/outside/rules=read",
		"--item", "sys/policies/acl/agent-grant-x=read",
		"--timeout", "2m",
	)
	pending := approver.waitForPending(ctx, t, "kv/data/e2e/alpha", "kv/data/e2e/beta")
	if requester := pending.GetRequester(); pending.GetReason() != "e2e: deploy needs alpha and beta" || requester.GetId() != "e2e-project-a" || requester.GetRule() != "named" {
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

	assertRead(ctx, t, bao, identityA.Token, "alpha", http.StatusOK)
	assertRead(ctx, t, bao, identityA.Token, "beta", http.StatusForbidden)
	read := cred.run(ctx, t, identityA.env(), "read", "--field", "data.value", "kv/data/e2e/alpha")
	if read.exitCode != 0 || read.stdout != "secret-alpha" {
		t.Fatalf("bao-cred read = %+v", read)
	}

	// A project token's requests default to project scope: the Grant lives in
	// the project policy the token carries, and nothing is attached to its
	// entity.
	mustCall(t, ctx, bao, rootToken, http.MethodGet, "sys/policies/acl/agent-grant-project-e2e-project-a", nil, http.StatusOK)
	if policies := entityGrantPolicies(ctx, t, bao, identityA.EntityID); len(policies) != 0 {
		t.Fatalf("identity A entity grant policies = %v, want none", policies)
	}

	t.Log("approved item works for identity A's existing token through its project policy; rejected and refused items do not")

	// Asking again for something OpenBao already allows needs no approver.
	repeat := cred.run(ctx, t, identityA.env(), "request", "--reason", "e2e: again", "--item", "kv/data/e2e/alpha=read", "--timeout", "30s")
	if repeat.exitCode != 0 || itemStates(t, repeat.stdout)["kv/data/e2e/alpha"] != "already_granted" {
		t.Fatalf("repeated request = %+v", repeat)
	}

	if requests := approver.list(ctx, t, authorizerv1.GrantRequestFilter_GRANT_REQUEST_FILTER_PENDING); len(requests) != 0 {
		t.Fatalf("already granted item reached approvers: %+v", requests)
	}

	// A request filed without waiting can be resumed by its ID.
	filed := cred.run(ctx, t, identityA.env(), "request", "--reason", "e2e: gamma", "--item", "kv/data/e2e/gamma=read", "--no-wait")
	if filed.exitCode != exitPending {
		t.Fatalf("no-wait request = %+v", filed)
	}

	gamma := approver.waitForPending(ctx, t, "kv/data/e2e/gamma")
	approver.decide(ctx, t, gamma, map[string]authorizerv1.Decision{"kv/data/e2e/gamma": authorizerv1.Decision_DECISION_APPROVE}, nil)
	resumed := cred.run(ctx, t, identityA.env(), "request", "--wait", requestID(t, filed.stdout), "--timeout", "30s")
	if resumed.exitCode != 0 || itemStates(t, resumed.stdout)["kv/data/e2e/gamma"] != "approved" {
		t.Fatalf("resumed wait = %+v", resumed)
	}

	assertRead(ctx, t, bao, identityA.Token, "gamma", http.StatusOK)
	t.Log("already-granted items skip approval; a request filed with --no-wait resumes with --wait")

	// Grants belong to the Named Identity, not to other identities, and
	// survive a re-mint, which revokes the previous token.
	identityB := cred.auth(ctx, t, "e2e-project-b")
	if identityB.EntityID == identityA.EntityID {
		t.Fatal("identities A and B share an entity")
	}

	assertRead(ctx, t, bao, identityB.Token, "alpha", http.StatusForbidden)
	previousA := identityA
	identityA = cred.auth(ctx, t, "e2e-project-a")
	if identityA.EntityID != previousA.EntityID || identityA.Token == previousA.Token {
		t.Fatalf("re-minted identity A = %+v, previous %+v", identityA, previousA)
	}

	mustCall(t, ctx, bao, previousA.Token, http.MethodGet, "auth/token/lookup-self", nil, http.StatusForbidden)
	assertRead(ctx, t, bao, identityA.Token, "alpha", http.StatusOK)
	t.Log("identity B cannot use A's grant; re-minting A revoked its old token and kept its Grants")

	// bao-cred env exports the Named Token for .envrc and status reports it.
	exported := cred.run(ctx, t, identityA.env(), "env")
	if exported.exitCode != 0 || !strings.Contains(exported.stdout, "export BAO_TOKEN='"+identityA.Token+"'") || !strings.Contains(exported.stdout, "export BAO_NO_TOKEN_FILE='1'") {
		t.Fatalf("bao-cred env = %+v", exported)
	}

	if status := cred.run(ctx, t, identityA.env(), "status"); status.exitCode != 0 || !strings.Contains(status.stdout, `"identity": "e2e-project-a"`) {
		t.Fatalf("bao-cred status = %+v", status)
	}

	missing := cred.run(ctx, t, []string{"BAO_IDENTITY=e2e-unknown"}, "read", "kv/data/e2e/alpha")
	if missing.exitCode != 1 || !strings.Contains(missing.stderr, "bao-cred auth e2e-unknown") {
		t.Fatalf("read with an identity that has no token = %+v", missing)
	}

	t.Log("bao-cred env exported the Named Token; an identity without a token fails closed instead of using ~/.vault-token")

	// Agent sessions: commands with OPENCODE_SESSION_ID get a session token
	// minted from the project token, carrying the project and global Grant
	// policies, with an entity of their own.
	session1 := append(identityA.env(), "OPENCODE_SESSION_ID=ses_E2E1")
	session2 := append(identityA.env(), "OPENCODE_SESSION_ID=ses_E2E2")
	if status := cred.run(ctx, t, session1, "status"); status.exitCode != 0 || !strings.Contains(status.stdout, `"session": "ses_E2E1"`) {
		t.Fatalf("bao-cred status in a session = %+v", status)
	}

	token1 := cred.sessionToken(t, "e2e-project-a", "ses_E2E1")
	var lookup struct {
		Data struct {
			EntityID string   `json:"entity_id"`
			Policies []string `json:"policies"`
		} `json:"data"`
	}
	decodeResponse(t, mustCall(t, ctx, bao, token1, http.MethodGet, "auth/token/lookup-self", nil, http.StatusOK), &lookup)
	if lookup.Data.EntityID == "" || lookup.Data.EntityID == identityA.EntityID ||
		!slices.Contains(lookup.Data.Policies, "agent-grant-project-e2e-project-a") || !slices.Contains(lookup.Data.Policies, "agent-grant-global") {
		t.Fatalf("session token = %+v", lookup.Data)
	}

	session1Entity := lookup.Data.EntityID
	assertRead(ctx, t, bao, token1, "alpha", http.StatusOK)
	t.Log("a session token was minted from the project token with its own entity; project A's Grants reach it")

	// A session request defaults to session scope: only that session gets it.
	sessionRead := cred.start(ctx, session1, "read", "--reason", "e2e: session iota", "--field", "data.value", "--timeout", "2m", "kv/data/e2e/iota")
	iotaRequest := approver.waitForPending(ctx, t, "kv/data/e2e/iota")
	if requester := iotaRequest.GetRequester(); requester.GetSession() != "ses_E2E1" || requester.GetProject() != "e2e-project-a" || len(requester.GetScopes()) != 3 ||
		iotaRequest.GetItems()[0].GetScope() != authorizerv1.Scope_SCOPE_SESSION {
		t.Fatalf("approver view of a session request = %+v", iotaRequest)
	}

	approver.decide(ctx, t, iotaRequest, map[string]authorizerv1.Decision{"kv/data/e2e/iota": authorizerv1.Decision_DECISION_APPROVE}, nil)
	if result := sessionRead.wait(t); result.exitCode != 0 || result.stdout != "secret-iota" {
		t.Fatalf("session read = %+v", result)
	}

	token2 := cred.run(ctx, t, session2, "run", "--", "/bin/sh", "-c", `printf %s "$BAO_TOKEN"`)
	if token2.exitCode != 0 || token2.stdout == "" || token2.stdout == token1 {
		t.Fatalf("bao-cred run in session 2 = %+v", token2)
	}

	assertRead(ctx, t, bao, token2.stdout, "iota", http.StatusForbidden)
	assertRead(ctx, t, bao, identityA.Token, "iota", http.StatusForbidden)
	if policies := entityGrantPolicies(ctx, t, bao, session1Entity); len(policies) != 1 {
		t.Fatalf("session 1 entity grant policies = %v, want its session policy", policies)
	}

	t.Log("a session-scope Grant reached only its session; bao-cred run handed session 2 its own token")

	// The Approver widens a project request to global: every project's
	// tokens, here identity B's, get it.
	globalRequest := cred.start(ctx, session2, "request", "--reason", "e2e: kappa for everyone", "--item", "kv/data/e2e/kappa=read", "--scope", "project", "--timeout", "2m")
	kappa := approver.waitForPending(ctx, t, "kv/data/e2e/kappa")
	if kappa.GetItems()[0].GetScope() != authorizerv1.Scope_SCOPE_PROJECT {
		t.Fatalf("requested scope = %s", kappa.GetItems()[0].GetScope())
	}

	approver.decideScoped(ctx, t, kappa, "kv/data/e2e/kappa", authorizerv1.Scope_SCOPE_GLOBAL)
	if result := globalRequest.wait(t); result.exitCode != 0 || !strings.Contains(result.stdout, `"scope": "global"`) {
		t.Fatalf("widened request = %+v", result)
	}

	for _, token := range []string{token1, identityA.Token, identityB.Token} {
		assertRead(ctx, t, bao, token, "kappa", http.StatusOK)
	}

	if grants := cred.run(ctx, t, identityB.env(), "grants"); grants.exitCode != 0 || !strings.Contains(grants.stdout, `"scope": "global"`) {
		t.Fatalf("identity B grants = %+v", grants)
	}

	t.Log("the Approver widened a project request to global; tokens of every project read it")

	// A short-lived Grant's block lapses through OpenBao's own expiration while
	// the other blocks of the Requester policy keep working.
	short := cred.start(ctx, identityA.env(), "request", "--reason", "e2e: brief delta", "--item", "kv/data/e2e/delta=read", "--ttl", "5s", "--timeout", "2m")
	delta := approver.waitForPending(ctx, t, "kv/data/e2e/delta")
	approver.decide(ctx, t, delta, map[string]authorizerv1.Decision{"kv/data/e2e/delta": authorizerv1.Decision_DECISION_APPROVE}, nil)
	if result := short.wait(t); result.exitCode != 0 {
		t.Fatalf("short grant request = %+v", result)
	}

	assertRead(ctx, t, bao, identityA.Token, "delta", http.StatusOK)
	waitForRead(ctx, t, bao, identityA.Token, "delta", http.StatusForbidden, 20*time.Second)
	assertRead(ctx, t, bao, identityA.Token, "alpha", http.StatusOK)
	t.Log("a 5s Grant stopped working after it expired; alpha still works")

	// Revoking a Grant takes effect immediately.
	grantID := approver.activeGrant(ctx, t, "e2e-project-a", "kv/data/e2e/gamma")
	if _, revokeErr := approver.rpc.RevokeGrant(ctx, connect.NewRequest(&authorizerv1.RevokeGrantRequest{GrantId: grantID})); revokeErr != nil {
		t.Fatalf("revoke Grant: %v", revokeErr)
	}

	assertRead(ctx, t, bao, identityA.Token, "gamma", http.StatusForbidden)
	assertRead(ctx, t, bao, identityA.Token, "alpha", http.StatusOK)
	t.Log("revoking one Grant removed only that access")

	// A read with --reason files a request on permission denied and retries after approval.
	autoRead := cred.start(ctx, identityA.env(), "read", "--reason", "e2e: read epsilon", "--field", "data.value", "--timeout", "2m", "kv/data/e2e/epsilon")
	epsilon := approver.waitForPending(ctx, t, "kv/data/e2e/epsilon")
	approver.decide(ctx, t, epsilon, map[string]authorizerv1.Decision{"kv/data/e2e/epsilon": authorizerv1.Decision_DECISION_APPROVE}, nil)
	if result := autoRead.wait(t); result.exitCode != 0 || result.stdout != "secret-epsilon" {
		t.Fatalf("auto-requesting read = %+v", result)
	}

	withoutReason := cred.run(ctx, t, identityB.env(), "read", "kv/data/e2e/epsilon")
	if withoutReason.exitCode != 1 || !strings.Contains(withoutReason.stderr, "--reason") {
		t.Fatalf("denied read without --reason = %+v", withoutReason)
	}

	grants := cred.run(ctx, t, identityA.env(), "grants")
	if grants.exitCode != 0 || !strings.Contains(grants.stdout, "kv/data/e2e/alpha") || !strings.Contains(grants.stdout, "kv/data/e2e/epsilon") || strings.Contains(grants.stdout, "kv/data/e2e/gamma") {
		t.Fatalf("bao-cred grants = %+v", grants)
	}

	t.Log("bao-cred read --reason requested access on denial and read the secret after approval")

	// A Requester finds a concrete path in the catalog and requests it.
	catalog := cred.run(ctx, t, identityB.env(), "grantable")
	var grantables []struct {
		Name          string   `json:"name"`
		Path          string   `json:"path"`
		MaxTTL        string   `json:"max_ttl"`
		Description   string   `json:"description"`
		Paths         []string `json:"paths"`
		DiscoverError string   `json:"discover_error"`
	}
	if catalog.exitCode != 0 || json.Unmarshal([]byte(catalog.stdout), &grantables) != nil || len(grantables) != 2 || grantables[1].Name != "e2e-ssh" {
		t.Fatalf("bao-cred grantable = %+v", catalog)
	}

	if rule := grantables[0]; rule.Name != "e2e-kv" || rule.Path != "kv/data/e2e/*" || rule.MaxTTL != "2h0m0s" || rule.Description != "E2E secrets" ||
		rule.DiscoverError != "" || !slices.Contains(rule.Paths, "kv/data/e2e/theta") || slices.Contains(rule.Paths, "kv/data/e2e/folder/") {
		t.Fatalf("e2e-kv grantable = %+v", rule)
	}

	theta := cred.start(ctx, identityB.env(), "read", "--reason", "e2e: theta from the catalog", "--field", "data.value", "--timeout", "2m", "kv/data/e2e/theta")
	thetaRequest := approver.waitForPending(ctx, t, "kv/data/e2e/theta")
	approver.decide(ctx, t, thetaRequest, map[string]authorizerv1.Decision{"kv/data/e2e/theta": authorizerv1.Decision_DECISION_APPROVE}, nil)
	if result := theta.wait(t); result.exitCode != 0 || result.stdout != "secret-theta" {
		t.Fatalf("read of a discovered path = %+v", result)
	}

	t.Log("bao-cred grantable listed kv/data/e2e/theta from kv/metadata/e2e; reading it with --reason worked after approval")

	// A write with --reason requests update on denial, then has OpenBao sign
	// an SSH key with the role's fixed principal.
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SSH key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("SSH signer: %v", err)
	}

	publicKeyFile := filepath.Join(runtimeDirectory, "ssh-key.pub")
	certificateFile := filepath.Join(runtimeDirectory, "ssh-key-cert.pub")
	writeSecretFile(t, publicKeyFile, string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	signing := cred.start(ctx, identityB.env(), "write", "--reason", "e2e: ssh to e2e-node", "--field", "signed_key",
		"--output", certificateFile, "--timeout", "2m", "ssh/sign/e2e-node", "public_key=@"+publicKeyFile)
	signRequest := approver.waitForPending(ctx, t, "ssh/sign/e2e-node")
	approver.decide(ctx, t, signRequest, map[string]authorizerv1.Decision{"ssh/sign/e2e-node": authorizerv1.Decision_DECISION_APPROVE}, nil)
	if result := signing.wait(t); result.exitCode != 0 || result.stdout != "" {
		t.Fatalf("bao-cred write ssh/sign/e2e-node = %+v", result)
	}

	signed, err := os.ReadFile(certificateFile)
	if err != nil {
		t.Fatalf("read SSH certificate: %v", err)
	}

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(signed)
	certificate, isCertificate := parsedKey.(*ssh.Certificate)
	if err != nil || !isCertificate || certificate.CertType != ssh.UserCert ||
		!slices.Equal(certificate.ValidPrincipals, []string{"core@e2e-node"}) || !strings.HasPrefix(certificate.KeyId, "e2e-node-") ||
		!bytes.Equal(certificate.Key.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatalf("SSH certificate = %+v, %v", parsedKey, err)
	}

	if lifetime := time.Duration(certificate.ValidBefore-certificate.ValidAfter) * time.Second; lifetime > 6*time.Minute {
		t.Fatalf("SSH certificate lifetime = %s, want the role's 5m", lifetime)
	}

	t.Log("bao-cred write --reason requested update on ssh/sign/e2e-node and wrote a certificate for core@e2e-node only")

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
	assertRead(ctx, t, bao, identityA.Token, "zeta", http.StatusForbidden)

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

	mustCall(t, ctx, bao, authorizerToken, http.MethodPost, "identity/entity/id/"+identityA.EntityID, map[string]any{"name": "renamed"}, http.StatusForbidden)
	mustCall(t, ctx, bao, authorizerToken, http.MethodPost, "identity/entity/id/"+identityA.EntityID, map[string]any{"disabled": true}, http.StatusForbidden)
	mustCall(t, ctx, bao, authorizerToken, http.MethodPost, "sys/policies/acl/not-a-grant", map[string]string{"policy": "path \"kv/*\" { capabilities = [\"read\"] }"}, http.StatusForbidden)
	t.Log("the authorizer token cannot rename or disable entities or write other policies")

	// A session revokes the Grants it filed, and not one another session
	// filed, even though that Grant reaches it.
	var mine []struct {
		ID   string `json:"id"`
		Path string `json:"path"`
		Mine bool   `json:"mine"`
	}
	listed := cred.run(ctx, t, session1, "grants")
	decodeResponse(t, []byte(listed.stdout), &mine)
	ownedBy := map[string]string{}
	for _, grant := range mine {
		if grant.Mine {
			ownedBy[grant.Path] = grant.ID
		}
	}

	if _, ok := ownedBy["kv/data/e2e/iota"]; !ok || len(ownedBy) != 1 {
		t.Fatalf("session 1 grants marked mine = %v", ownedBy)
	}

	if revoked := cred.run(ctx, t, session1, "revoke", "--all"); revoked.exitCode != 0 || !strings.Contains(revoked.stdout, ownedBy["kv/data/e2e/iota"]) {
		t.Fatalf("bao-cred revoke --all = %+v", revoked)
	}

	assertRead(ctx, t, bao, token1, "iota", http.StatusForbidden)
	kappaID := approver.activeGrant(ctx, t, "ses_E2E2", "kv/data/e2e/kappa")
	if refused := cred.run(ctx, t, session1, "revoke", kappaID); refused.exitCode != 1 || !strings.Contains(refused.stderr, "not found") {
		t.Fatalf("revoking another session's Grant = %+v", refused)
	}

	assertRead(ctx, t, bao, token1, "kappa", http.StatusOK)
	t.Log("a session revoked its own Grant; another session's global Grant stayed")

	// Logout revokes the Named Token; the next command has no token.
	if logout := cred.run(ctx, t, identityA.env(), "logout"); logout.exitCode != 0 {
		t.Fatalf("bao-cred logout = %+v", logout)
	}

	mustCall(t, ctx, bao, identityA.Token, http.MethodGet, "auth/token/lookup-self", nil, http.StatusForbidden)
	// Session tokens are children of the Named Token and die with it.
	mustCall(t, ctx, bao, token1, http.MethodGet, "auth/token/lookup-self", nil, http.StatusForbidden)
	if afterLogout := cred.run(ctx, t, identityA.env(), "grants"); afterLogout.exitCode != 1 {
		t.Fatalf("bao-cred grants after logout = %+v", afterLogout)
	}

	t.Log("bao-cred logout revoked and deleted the Named Token")

	// bao-cred init names the identity in a committed file at the git root;
	// commands anywhere in the project then need no environment variables.
	// The developer's own token gets NOT_REQUESTER from GrantService, so a
	// working `grants` proves the Named Token was used.
	project := filepath.Join(runtimeDirectory, "e2e-project-c")
	for _, directory := range []string{filepath.Join(project, ".git"), filepath.Join(project, "src")} {
		if mkdirErr := os.MkdirAll(directory, 0o755); mkdirErr != nil {
			t.Fatalf("create project: %v", mkdirErr)
		}
	}

	if initialized := cred.runIn(ctx, t, project, nil, "init", "--store", "file"); initialized.exitCode != 0 || !strings.Contains(initialized.stdout, `"identity": "e2e-project-c"`) {
		t.Fatalf("bao-cred init = %+v", initialized)
	}

	// Its only Grant is the global one approved earlier.
	if listed := cred.runIn(ctx, t, filepath.Join(project, "src"), nil, "grants"); listed.exitCode != 0 ||
		!strings.Contains(listed.stdout, "kv/data/e2e/kappa") || strings.Contains(listed.stdout, "kv/data/e2e/alpha") {
		t.Fatalf("bao-cred grants inside the project = %+v", listed)
	}

	t.Log("bao-cred init wrote .bao-identity; bao-cred inside the project used its Named Token without environment variables")
	t.Log("real OpenBao Named Identity grant workflow passed")
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

type baoCred struct {
	binary     string
	paths      isolatedProcessPaths
	address    string
	authorizer string
}

// environment adds the OpenBao and authorizer addresses to requester, the
// variables that select the Requester's token.
func (c baoCred) environment(requester []string) []string {
	return c.paths.environment(append([]string{"BAO_ADDR=" + c.address, "BAO_AUTHORIZER_ADDR=" + c.authorizer}, requester...)...)
}

func (c baoCred) run(ctx context.Context, t *testing.T, requester []string, arguments ...string) processResult {
	t.Helper()
	return runProcess(ctx, c.environment(requester), c.binary, arguments...)
}

func (c baoCred) runIn(ctx context.Context, t *testing.T, directory string, requester []string, arguments ...string) processResult {
	t.Helper()
	return runProcessIn(ctx, directory, c.environment(requester), c.binary, arguments...)
}

func (c baoCred) start(ctx context.Context, requester []string, arguments ...string) *backgroundProcess {
	done := make(chan processResult, 1)
	go func() { done <- runProcess(ctx, c.environment(requester), c.binary, arguments...) }()
	return &backgroundProcess{done: done}
}

// namedIdentity is a Named Token minted by bao-cred auth.
type namedIdentity struct {
	Name     string
	Token    string
	EntityID string
	Store    string
	TTL      time.Duration
}

// sessionToken reads the session token bao-cred stored for an agent session.
func (c baoCred) sessionToken(t *testing.T, project, session string) string {
	t.Helper()
	token, err := os.ReadFile(filepath.Join(c.paths.home, ".local", "state", "bao-cred", "sessions", project, session+".token"))
	if err != nil {
		t.Fatalf("read session token: %v", err)
	}

	return strings.TrimSpace(string(token))
}

// env selects the identity the way a project's .envrc does.
func (i namedIdentity) env() []string { return []string{"BAO_IDENTITY=" + i.Name} }

// auth runs bao-cred auth with the developer's ~/.vault-token and reads the
// stored token back for direct OpenBao checks.
func (c baoCred) auth(ctx context.Context, t *testing.T, name string) namedIdentity {
	t.Helper()
	result := c.run(ctx, t, nil, "auth", "--store", "file", name)
	if result.exitCode != 0 {
		t.Fatalf("bao-cred auth %s = %+v", name, result)
	}

	var status struct {
		Identity string `json:"identity"`
		Store    string `json:"store"`
		EntityID string `json:"entity_id"`
		TTL      string `json:"ttl"`
	}
	decodeResponse(t, []byte(result.stdout), &status)
	ttl, err := time.ParseDuration(status.TTL)
	if err != nil || status.Identity != name {
		t.Fatalf("bao-cred auth %s status = %+v", name, status)
	}

	token, err := os.ReadFile(filepath.Join(c.paths.home, ".local", "state", "bao-cred", name+".token"))
	if err != nil {
		t.Fatalf("read stored Named Token: %v", err)
	}

	return namedIdentity{Name: name, Token: strings.TrimSpace(string(token)), EntityID: status.EntityID, Store: status.Store, TTL: ttl}
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
	return runProcessIn(ctx, "", environment, binary, arguments...)
}

func runProcessIn(ctx context.Context, directory string, environment []string, binary string, arguments ...string) processResult {
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Dir = directory
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

// decideScoped approves the item at path with scope.
func (a *approverClient) decideScoped(ctx context.Context, t *testing.T, request *authorizerv1.GrantRequest, path string, scope authorizerv1.Scope) {
	t.Helper()
	for _, item := range request.GetItems() {
		if item.GetPath() != path {
			continue
		}

		decision := &authorizerv1.ItemDecision{ItemId: item.GetId(), Decision: authorizerv1.Decision_DECISION_APPROVE, Scope: scope}
		if _, err := a.rpc.DecideItems(ctx, connect.NewRequest(&authorizerv1.DecideItemsRequest{
			GrantRequestId: request.GetId(), Decisions: []*authorizerv1.ItemDecision{decision},
		})); err != nil {
			t.Fatalf("decide items: %v", err)
		}

		return
	}

	t.Fatalf("no item %s in request %s", path, request.GetId())
}

// entityGrantPolicies lists the Grant policies attached to an entity.
func entityGrantPolicies(ctx context.Context, t *testing.T, bao *liveAPI, entityID string) []string {
	t.Helper()
	var entity struct {
		Data struct {
			Policies []string `json:"policies"`
		} `json:"data"`
	}
	decodeResponse(t, mustCall(t, ctx, bao, rootToken, http.MethodGet, "identity/entity/id/"+entityID, nil, http.StatusOK), &entity)
	return slices.DeleteFunc(entity.Data.Policies, func(name string) bool { return !strings.HasPrefix(name, "agent-grant-") })
}

func (a *approverClient) activeGrant(ctx context.Context, t *testing.T, requesterID, path string) string {
	t.Helper()
	response, err := a.rpc.ListGrants(ctx, connect.NewRequest(&authorizerv1.ListGrantsRequest{}))
	if err != nil {
		t.Fatalf("list Grants: %v", err)
	}

	for _, grant := range response.Msg.GetGrants() {
		if grant.GetPath() == path && grant.GetRequester().GetId() == requesterID {
			return grant.GetId()
		}
	}

	t.Fatalf("no active Grant for %s of Requester %s: %v", path, requesterID, response.Msg.GetGrants())
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
