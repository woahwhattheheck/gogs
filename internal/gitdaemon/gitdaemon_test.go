package gitdaemon

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gogs.io/gogs/internal/database"
)

func pktLine(payload string) string {
	return fmt.Sprintf("%04x%s", len(payload)+4, payload)
}

func TestReadPacketLine(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expErr    bool
		expOutput string
	}{
		{
			name:      "normal request",
			input:     pktLine("git-upload-pack /alice/repo.git\x00"),
			expOutput: "git-upload-pack /alice/repo.git\x00",
		},
		{
			name:   "truncated length",
			input:  "003",
			expErr: true,
		},
		{
			name:   "non-hex length",
			input:  "zzzz" + pktLine("git-upload-pack /a/b.git\x00"),
			expErr: true,
		},
		{
			name:   "zero length",
			input:  "0000",
			expErr: true,
		},
		{
			name:   "declared length shorter than pkt-line header",
			input:  "0004" + pktLine("git-upload-pack /a/b.git\x00"),
			expErr: true,
		},
		{
			name:   "oversized length",
			input:  "ffff" + pktLine("git-upload-pack /a/b.git\x00"),
			expErr: true,
		},
		{
			name:   "truncated payload",
			input:  pktLine("git-upload-pack /alice/repo.git\x00")[:10],
			expErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := readPacketLine(bytes.NewReader([]byte(test.input)))
			if test.expErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expOutput, string(got))
		})
	}
}

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		expErr     bool
		expService string
		expPath    string
		expOwner   string
		expRepo    string
	}{
		{
			name:       "upload-pack with host parameter",
			payload:    "git-upload-pack /Alice/Repo.git\x00host=example.com\x00",
			expService: "git-upload-pack",
			expPath:    "alice/repo.git",
			expOwner:   "alice",
			expRepo:    "repo",
		},
		{
			name:       "upload-pack with protocol version",
			payload:    "git-upload-pack /alice/repo.git\x00host=example.com\x00\x00version=1\x00",
			expService: "git-upload-pack",
			expPath:    "alice/repo.git",
			expOwner:   "alice",
			expRepo:    "repo",
		},
		{
			name:       "upload-archive",
			payload:    "git-upload-archive /alice/repo.git\x00",
			expService: "git-upload-archive",
			expPath:    "alice/repo.git",
			expOwner:   "alice",
			expRepo:    "repo",
		},
		{
			name:       "wiki repository",
			payload:    "git-upload-pack /alice/repo.wiki.git\x00host=example.com\x00",
			expService: "git-upload-pack",
			expPath:    "alice/repo.wiki.git",
			expOwner:   "alice",
			expRepo:    "repo",
		},
		{
			name:       "path without .git suffix",
			payload:    "git-upload-pack /alice/repo\x00host=example.com\x00",
			expService: "git-upload-pack",
			expPath:    "alice/repo",
			expOwner:   "alice",
			expRepo:    "repo",
		},
		{
			name:    "receive-pack is rejected",
			payload: "git-receive-pack /alice/repo.git\x00host=example.com\x00",
			expErr:  true,
		},
		{
			name:    "unknown service",
			payload: "git-whatever /alice/repo.git\x00",
			expErr:  true,
		},
		{
			name:    "missing path",
			payload: "git-upload-pack\x00host=example.com\x00",
			expErr:  true,
		},
		{
			name:    "path traversal",
			payload: "git-upload-pack /../../secret.git\x00host=example.com\x00",
			expErr:  true,
		},
		{
			name:    "dot segment",
			payload: "git-upload-pack /./repo.git\x00host=example.com\x00",
			expErr:  true,
		},
		{
			name:    "extra path segments",
			payload: "git-upload-pack /a/b/c.git\x00host=example.com\x00",
			expErr:  true,
		},
		{
			name:    "empty owner",
			payload: "git-upload-pack //repo.git\x00host=example.com\x00",
			expErr:  true,
		},
		{
			name:    "backslash traversal",
			payload: "git-upload-pack /..\\secret.git\x00host=example.com\x00",
			expErr:  true,
		},
		{
			name:    "empty payload",
			payload: "",
			expErr:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseRequest([]byte(test.payload))
			if test.expErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expService, got.service)
			assert.Equal(t, test.expPath, got.path)
			assert.Equal(t, test.expOwner, got.owner)
			assert.Equal(t, test.expRepo, got.repo)
		})
	}
}

func TestAnonymousGitReadPolicy(t *testing.T) {
	tests := []struct {
		name          string
		repo          database.Repository
		wiki          bool
		requireSignin bool
		want          bool
	}{
		{"public repository", database.Repository{}, false, false, true},
		{"public repository despite externally hosted wiki", database.Repository{EnableExternalWiki: true}, false, false, true},
		{"enabled internal wiki", database.Repository{EnableWiki: true}, true, false, true},
		{"disabled wiki", database.Repository{EnableWiki: false}, true, false, false},
		{"externally hosted wiki", database.Repository{EnableWiki: true, EnableExternalWiki: true}, true, false, false},
		{"private repository", database.Repository{IsPrivate: true}, false, false, false},
		{"private wiki", database.Repository{IsPrivate: true, EnableWiki: true}, true, false, false},
		{"sign-in required for repository", database.Repository{}, false, true, false},
		{"sign-in required for wiki", database.Repository{EnableWiki: true}, true, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, canServeAnonymousGit(&tc.repo, tc.wiki, tc.requireSignin))
		})
	}
}

func TestSendError(t *testing.T) {
	var buf bytes.Buffer
	sendError(&buf, "repository not found")

	// ERR message is sent as a single pkt-line: "<4-hex-len>ERR <msg>\n".
	got := buf.String()
	payload := fmt.Sprintf("ERR %s\n", "repository not found")
	assert.Equal(t, fmt.Sprintf("%04x%s", len(payload)+4, payload), got)
}
