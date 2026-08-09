package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testOpts(url string) Options {
	return Options{BaseURL: url, ServiceToken: "svc-secret", HTTPClient: &http.Client{Timeout: 2 * time.Second}}
}

func TestAuthClientResolvesIdentityFromSeamOnly(t *testing.T) {
	var gotServiceAuth, gotVerifyToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotServiceAuth = r.Header.Get("Authorization")
		gotVerifyToken = r.Header.Get("X-Verify-Token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"uid":"user-42","org_id":"org-7"}`))
	}))
	defer srv.Close()

	p, err := NewAuthClient(testOpts(srv.URL)).Authenticate(context.Background(), "browser-bearer")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.UserID != "user-42" || p.OrgID != "org-7" {
		t.Fatalf("identity = %+v, want user-42/org-7", p)
	}
	if gotServiceAuth != "Bearer svc-secret" {
		t.Errorf("service token not sent, got %q", gotServiceAuth)
	}
	if gotVerifyToken != "browser-bearer" {
		t.Errorf("bearer not forwarded, got %q", gotVerifyToken)
	}
}

func TestAuthClientEmptyCredentialFailsClosed(t *testing.T) {
	// No server should be hit for an empty credential.
	_, err := NewAuthClient(testOpts("http://127.0.0.1:0")).Authenticate(context.Background(), "")
	if err == nil {
		t.Fatal("empty credential must fail closed")
	}
}

func TestAuthClientNon2xxFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := NewAuthClient(testOpts(srv.URL)).Authenticate(context.Background(), "x"); err == nil {
		t.Fatal("non-2xx must fail closed")
	}
}

func TestAuthClientMissingUIDFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"org_id":"org-7"}`))
	}))
	defer srv.Close()
	if _, err := NewAuthClient(testOpts(srv.URL)).Authenticate(context.Background(), "x"); err == nil {
		t.Fatal("missing uid must fail closed")
	}
}

func TestSpaceClientMembership(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"member":true}`))
	}))
	defer srv.Close()
	ok, err := NewSpaceClient(testOpts(srv.URL)).IsMember(context.Background(), "org-7", "user-42")
	if err != nil || !ok {
		t.Fatalf("IsMember = %v,%v, want true,nil", ok, err)
	}
}

func TestSpaceClientFailsClosedOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	ok, err := NewSpaceClient(testOpts(srv.URL)).IsMember(context.Background(), "org-7", "user-42")
	if err == nil {
		t.Fatal("space seam error must be surfaced")
	}
	if ok {
		t.Fatal("membership must be false on error (fail closed)")
	}
}

func TestNotificationClientReportsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	err := NewNotificationClient(testOpts(srv.URL)).Notify(context.Background(), "user-42", "meeting_invite", map[string]any{"note": "需要入会密码"})
	if err == nil {
		t.Fatal("notification failure must be surfaced for deferred handling")
	}
}

func TestNotificationClientSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	if err := NewNotificationClient(testOpts(srv.URL)).Notify(context.Background(), "u", "t", nil); err != nil {
		t.Fatalf("Notify: %v", err)
	}
}

func TestSeamTimeoutFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"uid":"late"}`))
	}))
	defer srv.Close()
	opts := Options{BaseURL: srv.URL, HTTPClient: &http.Client{Timeout: 20 * time.Millisecond}}
	if _, err := NewAuthClient(opts).Authenticate(context.Background(), "x"); err == nil {
		t.Fatal("timeout must fail closed")
	}
}
