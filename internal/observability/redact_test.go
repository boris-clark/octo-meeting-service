package observability

import (
	"bytes"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// newTestLogger returns a logger writing JSON into buf, with redaction on.
func newTestLogger(buf *bytes.Buffer) *zap.Logger {
	enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(enc, zapcore.AddSync(buf), zapcore.DebugLevel)
	return zap.New(NewRedactingCore(core))
}

func TestRedact_MasksSensitiveField(t *testing.T) {
	var buf bytes.Buffer
	log := newTestLogger(&buf)
	log.Info("login", zap.String("password", "hunter2"), zap.String("user", "alice"))

	out := buf.String()
	if strings.Contains(out, "hunter2") {
		t.Fatalf("secret leaked into log output: %s", out)
	}
	if !strings.Contains(out, redacted) {
		t.Fatalf("expected redaction marker, got: %s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Fatalf("non-sensitive field should be preserved, got: %s", out)
	}
}

func TestRedact_WithFields(t *testing.T) {
	var buf bytes.Buffer
	log := newTestLogger(&buf).With(zap.String("livekit_token", "eyJ.secret"))
	log.Info("issue")

	if strings.Contains(buf.String(), "eyJ.secret") {
		t.Fatalf("secret leaked via With(): %s", buf.String())
	}
}

func TestIsSensitiveKey_CaseInsensitive(t *testing.T) {
	if !IsSensitiveKey("Authorization") {
		t.Fatal("expected Authorization to be sensitive")
	}
	if IsSensitiveKey("meeting_id") {
		t.Fatal("meeting_id should not be sensitive")
	}
}
