// Package observability wires structured logging, redaction, and metrics.
package observability

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewLogger builds a zap logger from a level and format ("json" or "console").
// It installs the redaction core so sensitive fields never reach the sink.
func NewLogger(level, format string) (*zap.Logger, error) {
	lvl := zap.NewAtomicLevel()
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("parse log level %q: %w", level, err)
	}

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	var enc zapcore.Encoder
	switch format {
	case "console":
		enc = zapcore.NewConsoleEncoder(encCfg)
	case "json", "":
		enc = zapcore.NewJSONEncoder(encCfg)
	default:
		return nil, fmt.Errorf("unsupported log format %q", format)
	}

	inner := zapcore.NewCore(enc, zapcore.Lock(zapcore.AddSync(os.Stderr)), lvl)
	return zap.New(NewRedactingCore(inner), zap.AddCaller()), nil
}
