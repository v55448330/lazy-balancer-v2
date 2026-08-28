package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/acme"
)

type cleanupTrackingProvider struct {
	mu       sync.Mutex
	presents int
	cleaned  []string
}

func (p *cleanupTrackingProvider) Present(context.Context, string, string, string, int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.presents++
	if p.presents == 2 {
		return errors.New("second present failed")
	}
	return nil
}

func (p *cleanupTrackingProvider) CleanUp(_ context.Context, _ string, tokenFQDN string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleaned = append(p.cleaned, tokenFQDN)
	return nil
}

func TestIssuer_Issue_cleans_presented_records_when_later_present_fails(t *testing.T) {
	// Given
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = fmt.Fprintf(response, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, serverURL+"/nonce", serverURL+"/account", serverURL+"/order")
		case "/nonce":
			response.WriteHeader(http.StatusOK)
		case "/account":
			response.Header().Set("Location", serverURL+"/account/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"status":"valid"}`))
		case "/order":
			response.Header().Set("Location", serverURL+"/order/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(response, `{"status":"pending","authorizations":[%q,%q],"finalize":%q}`, serverURL+"/auth/1", serverURL+"/auth/2", serverURL+"/finalize/1")
		case "/auth/1":
			_, _ = fmt.Fprintf(response, `{"status":"pending","identifier":{"type":"dns","value":"example.com"},"challenges":[{"type":"dns-01","url":%q,"status":"pending","token":"token-one"}]}`, serverURL+"/challenge/1")
		case "/auth/2":
			_, _ = fmt.Fprintf(response, `{"status":"pending","identifier":{"type":"dns","value":"www.example.com"},"challenges":[{"type":"dns-01","url":%q,"status":"pending","token":"token-two"}]}`, serverURL+"/challenge/2")
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	serverURL = server.URL
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	client := &Client{
		DirectoryURL: serverURL + "/directory",
		Email:        "admin@example.com",
		accountKey:   key,
		acme: &acme.Client{
			Key:          key,
			DirectoryURL: serverURL + "/directory",
			HTTPClient:   server.Client(),
		},
	}
	provider := &cleanupTrackingProvider{}
	issuer := &Issuer{Client: client, Provider: provider}

	// When
	_, _, _, issueErr := issuer.Issue(context.Background(), []string{"example.com", "www.example.com"})

	// Then
	if issueErr == nil {
		t.Fatal("issuance succeeded despite second DNS presentation failure")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	firstRecordCleanups := 0
	for _, record := range provider.cleaned {
		if record == "_acme-challenge.example.com." {
			firstRecordCleanups++
		}
	}
	if len(provider.cleaned) != 3 || firstRecordCleanups != 2 {
		t.Fatalf("cleaned records=%v, want stale cleanup for both records and deferred cleanup for the first", provider.cleaned)
	}
}

func TestTerminalAuthorizationError_prefers_authorization_error(t *testing.T) {
	authError := &acme.Error{ProblemType: "urn:auth", Detail: "authorization detail"}
	challengeError := &acme.Error{ProblemType: "urn:challenge", Detail: "challenge detail"}
	err := terminalAuthorizationError(
		"invalid",
		&acme.AuthorizationError{Errors: []error{authError}},
		&acme.Challenge{Error: challengeError},
	)
	if !strings.Contains(err.Error(), "authorization detail") || strings.Contains(err.Error(), "challenge detail") {
		t.Fatalf("terminal error=%q, want authorization detail only", err)
	}
}

// valueAwareProvider tracks TXT records by challenge value: CleanUpValue
// removes only the matching value, CleanUp removes everything.
type valueAwareProvider struct {
	mu            sync.Mutex
	presents      int
	failPresents  bool
	records       map[string]string
	cleanedValues []string
	cleanedAll    bool
}

func (p *valueAwareProvider) Present(_ context.Context, _, _, value string, _ int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.presents++
	if p.failPresents {
		return errors.New("present failed")
	}
	p.records[value] = "record-" + value
	return nil
}

func (p *valueAwareProvider) CleanUp(_ context.Context, _ string, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanedAll = true
	p.records = map[string]string{}
	return nil
}

func (p *valueAwareProvider) CleanUpValue(_ context.Context, _, _, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanedValues = append(p.cleanedValues, value)
	delete(p.records, value)
	return nil
}

func TestIssuer_preCleanup_spares_concurrent_challenge_values(t *testing.T) {
	// Given: a stub ACME server with one authorization
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = fmt.Fprintf(response, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, serverURL+"/nonce", serverURL+"/account", serverURL+"/order")
		case "/nonce":
			response.WriteHeader(http.StatusOK)
		case "/account":
			response.Header().Set("Location", serverURL+"/account/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = response.Write([]byte(`{"status":"valid"}`))
		case "/order":
			response.Header().Set("Location", serverURL+"/order/1")
			response.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(response, `{"status":"pending","authorizations":[%q],"finalize":%q}`, serverURL+"/auth/1", serverURL+"/finalize/1")
		case "/auth/1":
			_, _ = fmt.Fprintf(response, `{"status":"pending","identifier":{"type":"dns","value":"example.com"},"challenges":[{"type":"dns-01","url":%q,"status":"pending","token":"token-one"}]}`, serverURL+"/challenge/1")
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	serverURL = server.URL
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	client := &Client{
		DirectoryURL: serverURL + "/directory",
		Email:        "admin@example.com",
		accountKey:   key,
		acme: &acme.Client{
			Key:          key,
			DirectoryURL: serverURL + "/directory",
			HTTPClient:   server.Client(),
		},
	}
	keyAuth, err := client.DNS01ChallengeRecord("token-one")
	if err != nil {
		t.Fatalf("derive key auth: %v", err)
	}
	provider := &valueAwareProvider{
		records: map[string]string{
			keyAuth:           "own-leftover", // stale record from a previous attempt of the same order
			"concurrent-live": "another-job",  // young record of a live concurrent issuance
		},
		failPresents: true,
	}
	issuer := &Issuer{Client: client, Provider: provider}

	// When: issuance starts (pre-cleanup runs before Present fails)
	_, _, _, issueErr := issuer.Issue(context.Background(), []string{"example.com"})

	// Then
	if issueErr == nil {
		t.Fatal("issuance succeeded despite present failure")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.cleanedValues) != 1 || provider.cleanedValues[0] != keyAuth {
		t.Fatalf("cleaned values=%v, want exactly the current key auth", provider.cleanedValues)
	}
	if _, exists := provider.records["concurrent-live"]; !exists {
		t.Fatal("pre-cleanup deleted a live concurrent challenge's record")
	}
	if _, exists := provider.records[keyAuth]; exists {
		t.Fatal("pre-cleanup did not remove the same-value leftover")
	}
}
