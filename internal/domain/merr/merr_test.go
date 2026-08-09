package merr

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHTTPStatusKnownAndUnknown(t *testing.T) {
	if got := HTTPStatus(CredentialInvalid); got != 404 {
		t.Fatalf("CredentialInvalid = %d, want 404", got)
	}
	if got := HTTPStatus(PasswordRequired); got != 428 {
		t.Fatalf("PasswordRequired = %d, want 428", got)
	}
	if got := HTTPStatus(Code("MEETING_DOES_NOT_EXIST")); got != 500 {
		t.Fatalf("unknown code = %d, want 500 fallback", got)
	}
	if Known(Code("MEETING_DOES_NOT_EXIST")) {
		t.Fatal("unknown code reported as known")
	}
}

func TestErrorEnvelopeAndDetails(t *testing.T) {
	base := New(TooEarly, "not open yet")
	withDetail := base.WithDetail("earliest_join_at", "2026-08-09T00:00:00Z")

	if base.Details != nil {
		t.Fatal("WithDetail mutated the receiver")
	}
	if withDetail.Details["earliest_join_at"] != "2026-08-09T00:00:00Z" {
		t.Fatalf("detail not set: %+v", withDetail.Details)
	}
	if withDetail.HTTPStatus() != 409 {
		t.Fatalf("TooEarly status = %d, want 409", withDetail.HTTPStatus())
	}
	if withDetail.Error() != "MEETING_TOO_EARLY: not open yet" {
		t.Fatalf("unexpected Error(): %q", withDetail.Error())
	}
}

// snapshotError mirrors the errors.yaml entry shape for the contract test.
type snapshotError struct {
	Code       string `yaml:"code"`
	HTTPStatus int    `yaml:"http_status"`
}

type snapshotFile struct {
	Errors []snapshotError `yaml:"errors"`
}

// snapshotPath resolves the committed error catalog relative to this test file
// so the contract test does not depend on the working directory.
func snapshotPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	// internal/domain/merr -> repo root is three levels up.
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	return filepath.Join(root, "contracts", "snapshots", "r4-go-f0f482c0", "errors.yaml")
}

// TestCatalogMatchesSnapshot enforces that the Go catalog and the authoritative
// errors.yaml agree on the exact set of codes and their HTTP statuses, in both
// directions. This is the backend route contract test the design requires
// (architecture §14 / backend appendix §15).
func TestCatalogMatchesSnapshot(t *testing.T) {
	raw, err := os.ReadFile(snapshotPath(t))
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	var snap snapshotFile
	if err := yaml.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("parse snapshot: %v", err)
	}
	if len(snap.Errors) == 0 {
		t.Fatal("snapshot has no errors")
	}

	snapByCode := make(map[string]int, len(snap.Errors))
	for _, e := range snap.Errors {
		snapByCode[e.Code] = e.HTTPStatus
	}

	// Every snapshot code exists in the Go catalog with the same status.
	for code, status := range snapByCode {
		got, ok := catalog[Code(code)]
		if !ok {
			t.Errorf("snapshot code %q missing from Go catalog", code)
			continue
		}
		if got != status {
			t.Errorf("code %q: snapshot http_status=%d, Go catalog=%d", code, status, got)
		}
	}

	// Every Go catalog code exists in the snapshot (no extra codes leak out).
	for code := range catalog {
		if _, ok := snapByCode[string(code)]; !ok {
			t.Errorf("Go catalog code %q missing from snapshot", code)
		}
	}

	if len(snapByCode) != len(catalog) {
		t.Errorf("code count mismatch: snapshot=%d, catalog=%d", len(snapByCode), len(catalog))
	}
}
