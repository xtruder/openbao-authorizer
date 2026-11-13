package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// gitCredentialRenewBefore is how long a cached credential must still be
// valid to be reused, so it doesn't expire during the git command.
const gitCredentialRenewBefore = 5 * time.Minute

// cachedGitCredential is a password kept until shortly before it expires.
type cachedGitCredential struct {
	Password  string `json:"password"`
	ExpiresAt int64  `json:"expires_at"`
}

func newGitCredentialCommand() *cobra.Command {
	var (
		field   string
		noCache bool
	)
	command := &cobra.Command{
		Use:   "git-credential [--field FIELD] <openbao-path> get|store|erase",
		Short: "Act as a git credential helper that answers with an OpenBao credential",
		Long: `Implements git's credential helper protocol: get reads <openbao-path> and
answers with username x-access-token and the field FIELD (default token) as
the password, such as a GitHub App installation token from
github/token/project-<name>. An expires_at field becomes password_expiry_utc.

Such a credential is cached per Requester (Named Identity and Agent Session)
and path in $XDG_RUNTIME_DIR/bao-cred/git, mode 0600, and reused while it has
more than 5 minutes left, so every git command doesn't create a token. erase,
which git calls when the server rejects a credential, drops it; store does
nothing. --no-cache reads OpenBao every time.

On permission denied it files a Grant Request for <openbao-path>=read with the
reason from BAO_REASON, else "git access to <url>", and waits for a decision.

{owner} and {repo} in the path become the first two segments of the URL's
path, lowercased and without .git, so one helper serves every repository; git
sends the path only with useHttpPath. A repository whose path the catalog
doesn't list is refused before a request is filed. git passes the operation
after the arguments in the helper's command:

  [credential "https://github.com"]
      useHttpPath = true
      helper = "!bao-cred git-credential github/token/project-{owner}-{repo}"`,
		Example: `  git config --global credential.https://github.com.useHttpPath true
  git config --global credential.https://github.com.helper \
    '!bao-cred git-credential github/token/project-{owner}-{repo}'`,
		Args: func(_ *cobra.Command, arguments []string) error {
			if len(arguments) != 2 {
				return usageError(errors.New("git-credential needs an OpenBao path and an operation: get, store, or erase"))
			}

			return nil
		},
		RunE: func(command *cobra.Command, arguments []string) error {
			switch arguments[1] {
			case "get":
				return runGitCredentialGet(command.Context(), identityFlag(command), arguments[0], field, !noCache,
					command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
			case "erase":
				return runGitCredentialErase(identityFlag(command), arguments[0], command.InOrStdin())
			case "store":
				// get caches what it reads; git's copy adds nothing.
				_, err := io.Copy(io.Discard, command.InOrStdin())
				return err
			default:
				return usageError(fmt.Errorf("unknown git credential operation %q: use get, store, or erase", arguments[1]))
			}
		},
	}

	command.Flags().StringVar(&field, "field", "token", "dot path of the field that holds the password")
	command.Flags().BoolVar(&noCache, "no-cache", false, "read OpenBao on every get instead of reusing a cached credential")
	return command
}

func runGitCredentialGet(
	ctx context.Context, identity, path, field string, cache bool, stdin io.Reader, stdout, stderr io.Writer,
) error {
	request, err := readGitCredentialRequest(stdin)
	if err != nil {
		return err
	}

	templated := strings.Contains(path, "{owner}") || strings.Contains(path, "{repo}")
	if templated {
		if path, err = expandGitCredentialPath(path, request["path"]); err != nil {
			return err
		}
	}

	cacheFile := ""
	if cache {
		if cacheFile, err = gitCredentialCacheFile(identity, path, field); err != nil {
			return err
		}

		if cached, ok := readCachedGitCredential(cacheFile, time.Now()); ok {
			return writeGitCredential(stdout, cached)
		}
	}

	reason := grantReason("")
	if reason == "" {
		reason = "git access to " + gitCredentialURL(request)
	}

	opts := options{
		identity: identity, path: path, reason: reason,
		capabilities: []string{"read"}, timeout: defaultApprovalTimeout,
	}
	if templated {
		opts.beforeRequest = func(ctx context.Context, authorizer *authorizerClient) error {
			return checkCatalog(ctx, authorizer, opts.path, "%s isn't in the catalog, so this repository has no credential; known: %s")
		}
	}

	data, err := credentials(ctx, opts, stderr)
	if err != nil {
		return err
	}

	value, err := selectValue(data, field)
	if err != nil {
		return err
	}

	password, err := scalar(value)
	if err != nil || password == "" || strings.ContainsAny(password, "\n\x00") {
		return fmt.Errorf("%s at %s is not a usable password", field, path)
	}

	credential := cachedGitCredential{Password: password}
	if expires, ok := data["expires_at"].(string); ok {
		if at, parseErr := time.Parse(time.RFC3339, expires); parseErr == nil {
			credential.ExpiresAt = at.Unix()
		}
	}

	// Without an expiry there is no telling when a cached copy goes stale.
	if cacheFile != "" && credential.ExpiresAt != 0 {
		if err := writeCachedGitCredential(cacheFile, credential); err != nil {
			newProgress(stderr, false)("warning: " + err.Error())
		}
	}

	return writeGitCredential(stdout, credential)
}

func writeGitCredential(stdout io.Writer, credential cachedGitCredential) error {
	answer := "username=x-access-token\npassword=" + credential.Password + "\n"
	if credential.ExpiresAt != 0 {
		answer += fmt.Sprintf("password_expiry_utc=%d\n", credential.ExpiresAt)
	}

	_, err := io.WriteString(stdout, answer)
	return err
}

// runGitCredentialErase drops the cached credential git found rejected, so
// the next get reads a new one.
func runGitCredentialErase(identity, path string, stdin io.Reader) error {
	request, err := readGitCredentialRequest(stdin)
	if err != nil {
		return err
	}

	if strings.Contains(path, "{owner}") || strings.Contains(path, "{repo}") {
		if path, err = expandGitCredentialPath(path, request["path"]); err != nil {
			return nil //nolint:nilerr // Nothing was cached for a request get refused too.
		}
	}

	directory, err := requesterDirectory("git", identity)
	if err != nil {
		return err
	}

	// Every field's copy for the path: erase doesn't know get's --field.
	matches, _ := filepath.Glob(filepath.Join(directory, gitCredentialCacheName(path)+"-*.json"))
	for _, match := range matches {
		if err := os.Remove(match); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("drop cached credential: %w", err)
		}
	}

	return nil
}

// gitCredentialCacheFile is the Requester's cache file for path and field.
func gitCredentialCacheFile(identity, path, field string) (string, error) {
	directory, err := requesterDirectory("git", identity)
	if err != nil {
		return "", err
	}

	fieldHash := sha256.Sum256([]byte(field))
	return filepath.Join(directory, fmt.Sprintf("%s-%x.json", gitCredentialCacheName(path), fieldHash[:4])), nil
}

// gitCredentialCacheName names a path's cache files without its slashes.
func gitCredentialCacheName(path string) string {
	sum := sha256.Sum256([]byte(path))
	return fmt.Sprintf("%x", sum[:8])
}

func readCachedGitCredential(path string, now time.Time) (cachedGitCredential, bool) {
	var credential cachedGitCredential
	contents, err := os.ReadFile(path) // #nosec G304 -- the Requester's own cache file.
	if err != nil || json.Unmarshal(contents, &credential) != nil || credential.Password == "" {
		return credential, false
	}

	return credential, now.Add(gitCredentialRenewBefore).Unix() < credential.ExpiresAt
}

func writeCachedGitCredential(path string, credential cachedGitCredential) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create credential cache: %w", err)
	}

	// The cache's purpose; it is written with mode 0600 in a 0700 directory.
	contents, err := json.Marshal(credential) // #nosec G117
	if err != nil {
		return fmt.Errorf("encode cached credential: %w", err)
	}

	return writeFile(path, contents)
}

// expandGitCredentialPath fills {owner} and {repo} in path from the first
// two segments of the requested URL's path, lowercased, without .git.
func expandGitCredentialPath(path, urlPath string) (string, error) {
	segments := strings.Split(strings.Trim(urlPath, "/"), "/")
	if len(segments) < 2 || segments[0] == "" || segments[1] == "" {
		return "", errors.New("git sent no owner/repo path; set credential.useHttpPath = true for this host")
	}

	owner := strings.ToLower(segments[0])
	repo := strings.ToLower(strings.TrimSuffix(segments[1], ".git"))
	for _, value := range []string{owner, repo} {
		if !gitPathSegment(value) {
			return "", fmt.Errorf("unsupported owner or repository name %q", value)
		}
	}

	return strings.NewReplacer("{owner}", owner, "{repo}", repo).Replace(path), nil
}

// gitPathSegment allows the characters GitHub allows in owner and
// repository names, so nothing else reaches the OpenBao path.
func gitPathSegment(value string) bool {
	return value != "" && value != "." && value != ".." &&
		strings.Trim(value, "abcdefghijklmnopqrstuvwxyz0123456789-_.") == ""
}

// readGitCredentialRequest reads git's key=value lines up to a blank line.
func readGitCredentialRequest(stdin io.Reader) (map[string]string, error) {
	request := map[string]string{}
	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}

		if key, value, ok := strings.Cut(line, "="); ok {
			request[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read the credential request: %w", err)
	}

	return request, nil
}

func gitCredentialURL(request map[string]string) string {
	url := request["protocol"] + "://" + request["host"]
	if path := request["path"]; path != "" {
		url += "/" + path
	}

	return url
}
