// Package gitdaemon provides a built-in Git protocol (git://) server that
// allows anonymous cloning of public repositories, the same way as the
// standalone "git daemon" command does.
package gitdaemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	log "unknwon.dev/clog/v2"

	"gogs.io/gogs/internal/conf"
	"gogs.io/gogs/internal/database"
)

// allowedServices are read-only Git services permitted for anonymous access.
var allowedServices = map[string]bool{
	"git-upload-pack":    true,
	"git-upload-archive": true,
}

// maxRequestLineLen is the sanity bound for the initial service request.
const maxRequestLineLen = 1024

// request is a parsed Git protocol service request.
type request struct {
	service     string // e.g. "git-upload-pack"
	path        string // repository path relative to the repository root, e.g. "owner/repo.git"
	owner       string // lowercased owner name for database lookup
	repo        string // lowercased repository name for database lookup
	gitProtocol string // explicitly requested, supported protocol negotiation (v1 or v2)
}

// readPacketLine reads a single pkt-line from r and returns its payload.
func readPacketLine(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, errors.Wrap(err, "read pkt-line length")
	}
	n, err := strconv.ParseUint(string(lenBuf[:]), 16, 16)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid pkt-line length %q", string(lenBuf[:]))
	}
	if n <= 4 || n > maxRequestLineLen {
		return nil, errors.Errorf("pkt-line length %d out of range", n)
	}
	payload := make([]byte, n-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, errors.Wrap(err, "read pkt-line payload")
	}
	return payload, nil
}

// packetWrite returns str encoded as a pkt-line.
func packetWrite(str string) string {
	return fmt.Sprintf("%04x%s", len(str)+4, str)
}

// sendError reports a protocol error to the client using the ERR pkt-line
// convention used by "git daemon".
func sendError(w io.Writer, msg string) {
	_, _ = io.WriteString(w, packetWrite(fmt.Sprintf("ERR %s\n", msg)))
}

// requestedGitProtocol reads only the wire-defined "version" parameter, which
// comes after the host field and an empty NUL-delimited separator. Never pass
// arbitrary client-provided environment variables or unrecognized parameters
// through to Git. Git protocol v2 requires GIT_PROTOCOL=version=2 for upload-pack.
func requestedGitProtocol(payload []byte) string {
	parts := strings.Split(string(payload), "\x00")
	if len(parts) < 5 || parts[2] != "" {
		return ""
	}
	for _, part := range parts[3 : len(parts)-1] {
		if part == "version=1" || part == "version=2" {
			return part
		}
	}
	return ""
}

// parseRequest parses the initial service request of the Git protocol, which
// has the form "<service> <path>\x00<extra-parameters>...", e.g.
// "git-upload-pack /owner/repo.git\x00host=example.com\x00".
func parseRequest(payload []byte) (*request, error) {
	// Repository request precedes NUL-separated host and optional protocol version.
	line, _, _ := strings.Cut(string(payload), "\x00")

	fields := strings.Fields(line)
	if len(fields) != 2 {
		return nil, errors.Errorf("malformed service request %q", line)
	}
	service, repoPath := fields[0], fields[1]
	if !allowedServices[service] {
		return nil, errors.Errorf("service %q is not allowed", service)
	}

	// The path must have the form "<owner>/<repo>.git" (or "<owner>/<repo>.wiki.git"
	// for wikis). Resolve the repository name and reject anything else,
	// including traversal attempts.
	repoPath = strings.TrimPrefix(repoPath, "/")
	name := strings.TrimSuffix(repoPath, ".git")
	fields = strings.Split(name, "/")
	if len(fields) != 2 || strings.ContainsAny(repoPath, "\\") {
		return nil, errors.Errorf("invalid repository path %q", repoPath)
	}
	ownerName, repoName := fields[0], fields[1]
	if ownerName == "" || repoName == "" || ownerName == "." || repoName == "." ||
		strings.HasPrefix(ownerName, "..") || strings.HasPrefix(repoName, "..") {
		return nil, errors.Errorf("invalid repository path %q", repoPath)
	}
	repoName = strings.TrimSuffix(repoName, ".wiki")

	return &request{
		service: service,
		path:    strings.ToLower(repoPath),
		owner:   strings.ToLower(ownerName),
		repo:    strings.ToLower(repoName),
		gitProtocol: requestedGitProtocol(payload),
	}, nil
}

// canServeAnonymousGit enforces the repository visibility policy and prevents
// wiki Git URLs from bypassing disabled or externally hosted wiki settings.
func canServeAnonymousGit(repo *database.Repository, wiki, requireSignin bool) bool {
	if repo.IsPrivate || requireSignin {
		return false
	}
	return !wiki || (repo.EnableWiki && !repo.EnableExternalWiki)
}

// handleConn serves a single Git protocol connection.
func handleConn(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()
	remote := conn.RemoteAddr()
	log.Trace("Git protocol: connection from %s", remote)

	fail := func(msg string, err error) {
		if err != nil {
			log.Trace("Git protocol: %s [%s]: %v", msg, remote, err)
		}
		sendError(conn, msg)
	}

	// The client is expected to send the service request promptly.
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		log.Trace("Git protocol: failed to set handshake deadline [%s]: %v", remote, err)
		return
	}
	payload, err := readPacketLine(conn)
	if err != nil {
		fail("protocol error", err)
		return
	}
	req, err := parseRequest(payload)
	if err != nil {
		fail("no such repository", err)
		return
	}

	ctx := context.Background()
	owner, err := database.Handle.Users().GetByUsername(ctx, req.owner)
	if err != nil {
		if !database.IsErrUserNotExist(err) {
			log.Error("Git protocol: failed to get owner %q: %v", req.owner, err)
		}
		fail("repository not found", nil)
		return
	}
	repo, err := database.GetRepositoryByName(owner.ID, req.repo)
	if err != nil {
		if !database.IsErrRepoNotExist(err) {
			log.Error("Git protocol: failed to get repository %q/%q: %v", req.owner, req.repo, err)
		}
		fail("repository not found", nil)
		return
	}

	// Public Git access must not expose a disabled or externally hosted wiki.
	if !canServeAnonymousGit(repo, strings.HasSuffix(req.path, ".wiki.git"), conf.Auth.RequireSigninView) {
		fail("access denied", nil)
		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		log.Trace("Git protocol: failed to clear deadline [%s]: %v", remote, err)
		return
	}

	// Delegate the session to the Git backend, e.g. "git upload-pack owner/repo.git".
	cmd := exec.Command("git", strings.TrimPrefix(req.service, "git-"), req.path)
	cmd.Dir = conf.Repository.Root
	// Without this, Git always answers with the legacy advertisement even if
	// a modern git:// client requested protocol v2. Explicitly override any
	// inherited value, and forward only recognized, protocol-defined versions.
	if req.service == "git-upload-pack" {
		cmd.Env = append(os.Environ(), "GIT_PROTOCOL="+req.gitProtocol)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Error("Git protocol: StdinPipe: %v", err)
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Error("Git protocol: StdoutPipe: %v", err)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Error("Git protocol: StderrPipe: %v", err)
		return
	}

	if err = cmd.Start(); err != nil {
		log.Error("Git protocol: failed to start %q [%s]: %v", req.service, remote, err)
		return
	}

	go func() {
		_, _ = io.Copy(stdin, conn)
		_ = stdin.Close()
	}()
	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()
	_, _ = io.Copy(conn, stdout)

	if err = cmd.Wait(); err != nil {
		log.Trace("Git protocol: %q exited for %s: %v", req.service, remote, err)
	}
}

// Listen starts a Git protocol server listening on the given host and port.
func Listen(opts conf.GitProtocolOpts) {
	listener, err := net.Listen("tcp", net.JoinHostPort(opts.ListenHost, strconv.Itoa(opts.ListenPort)))
	if err != nil {
		log.Fatal("Git protocol: failed to start server: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Error("Git protocol: error accepting incoming connection: %v", err)
				continue
			}
			go handleConn(conn)
		}
	}()
}
