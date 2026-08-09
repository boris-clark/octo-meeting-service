// Package config loads and validates service configuration from environment
// variables and optional config files. Secrets are never logged.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the fully-validated runtime configuration for both the API and
// worker entrypoints.
type Config struct {
	Env        string           `mapstructure:"env"`
	HTTP       HTTPConfig       `mapstructure:"http"`
	MySQL      MySQLConfig      `mapstructure:"mysql"`
	Redis      RedisConfig      `mapstructure:"redis"`
	Worker     WorkerConfig     `mapstructure:"worker"`
	Log        LogConfig        `mapstructure:"log"`
	Seams      SeamsConfig      `mapstructure:"seams"`
	LiveKit    LiveKitConfig    `mapstructure:"livekit"`
	Credential CredentialConfig `mapstructure:"credential"`
	Internal   InternalConfig   `mapstructure:"internal"`
	Shutdown   ShutdownConfig   `mapstructure:"shutdown"`
}

// HTTPConfig controls the public HTTP listener. The service mounts its own
// routes under BasePath ("/v1"); the gateway is expected to expose them under
// "/meeting/api/v1".
type HTTPConfig struct {
	Addr           string        `mapstructure:"addr"`
	BasePath       string        `mapstructure:"base_path"`
	ReadTimeout    time.Duration `mapstructure:"read_timeout"`
	WriteTimeout   time.Duration `mapstructure:"write_timeout"`
	MetricsAddr    string        `mapstructure:"metrics_addr"`
	TrustedProxies []string      `mapstructure:"trusted_proxies"`
}

// MySQLConfig configures the primary datastore. Migrations are applied with
// sql-migrate; the service never auto-creates a SQLite database.
type MySQLConfig struct {
	DSN             string        `mapstructure:"dsn"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// RedisConfig configures the Redis client used for leases and idempotency.
type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// WorkerConfig controls the background worker's bounded concurrency.
type WorkerConfig struct {
	Concurrency int           `mapstructure:"concurrency"`
	PollBackoff time.Duration `mapstructure:"poll_backoff"`
}

// LogConfig controls structured logging.
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// SeamsConfig holds the endpoints for external systems the service integrates
// with (auth/Space/notification verify seams and the LiveKit control plane).
// The API entrypoint builds fail-closed HTTP clients from these endpoints.
type SeamsConfig struct {
	Auth         SeamEndpoint `mapstructure:"auth"`
	Space        SeamEndpoint `mapstructure:"space"`
	Notification SeamEndpoint `mapstructure:"notification"`
	LiveKit      SeamEndpoint `mapstructure:"livekit"`
}

// SeamEndpoint is a single upstream dependency address.
type SeamEndpoint struct {
	BaseURL string        `mapstructure:"base_url"`
	Timeout time.Duration `mapstructure:"timeout"`
}

// LiveKitConfig holds the LiveKit control-plane credentials used to mint access
// tokens. Empty API key/secret leaves token minting unavailable (finalize then
// returns MEETING_LIVEKIT_UNAVAILABLE) rather than minting an invalid token.
type LiveKitConfig struct {
	URL       string        `mapstructure:"url"`
	APIKey    string        `mapstructure:"api_key"`
	APISecret string        `mapstructure:"api_secret"`
	TokenTTL  time.Duration `mapstructure:"token_ttl"`
}

// CredentialConfig holds the HMAC secret used to derive credential lookup
// hashes (meeting number / link token). Empty disables number/link resolution.
type CredentialConfig struct {
	LookupSecret string `mapstructure:"lookup_secret"`
}

// InternalConfig holds service-to-service credentials for seam calls.
type InternalConfig struct {
	ServiceToken string `mapstructure:"service_token"`
}

// ShutdownConfig controls graceful shutdown timing shared by both entrypoints.
type ShutdownConfig struct {
	GracePeriod time.Duration `mapstructure:"grace_period"`
}

// Load reads configuration from environment variables (prefix OCTO_MEETING_)
// and an optional config file, then validates required fields. Nested keys use
// "__" as the environment delimiter, e.g. OCTO_MEETING_MYSQL__DSN.
func Load() (*Config, error) {
	v := viper.New()
	v.SetEnvPrefix("OCTO_MEETING")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "__"))
	v.AutomaticEnv()

	setDefaults(v)
	bindEnv(v)

	if path := v.GetString("config_file"); path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config file %q: %w", path, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("env", "development")
	v.SetDefault("http.addr", ":8080")
	v.SetDefault("http.base_path", "/v1")
	v.SetDefault("http.read_timeout", "15s")
	v.SetDefault("http.write_timeout", "15s")
	v.SetDefault("http.metrics_addr", ":9090")
	v.SetDefault("mysql.max_open_conns", 20)
	v.SetDefault("mysql.max_idle_conns", 5)
	v.SetDefault("mysql.conn_max_lifetime", "30m")
	v.SetDefault("redis.db", 0)
	v.SetDefault("worker.concurrency", 4)
	v.SetDefault("worker.poll_backoff", "2s")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("seams.auth.timeout", "3s")
	v.SetDefault("seams.space.timeout", "3s")
	v.SetDefault("seams.notification.timeout", "3s")
	v.SetDefault("livekit.token_ttl", "90s")
	v.SetDefault("shutdown.grace_period", "20s")
}

// bindEnv explicitly binds every configuration key to its environment variable.
// This is required because viper's AutomaticEnv does not populate keys that have
// no default (e.g. secrets) when the config is later decoded with Unmarshal.
func bindEnv(v *viper.Viper) {
	keys := []string{
		"env",
		"http.addr", "http.base_path", "http.read_timeout", "http.write_timeout",
		"http.metrics_addr", "http.trusted_proxies",
		"mysql.dsn", "mysql.max_open_conns", "mysql.max_idle_conns", "mysql.conn_max_lifetime",
		"redis.addr", "redis.password", "redis.db",
		"worker.concurrency", "worker.poll_backoff",
		"log.level", "log.format",
		"seams.auth.base_url", "seams.auth.timeout",
		"seams.space.base_url", "seams.space.timeout",
		"seams.notification.base_url", "seams.notification.timeout",
		"seams.livekit.base_url", "seams.livekit.timeout",
		"livekit.url", "livekit.api_key", "livekit.api_secret", "livekit.token_ttl",
		"credential.lookup_secret",
		"internal.service_token",
		"shutdown.grace_period",
	}
	for _, k := range keys {
		_ = v.BindEnv(k)
	}
}

// Validate enforces the invariants required for a safe startup. It deliberately
// fails closed: a missing datastore DSN or Redis address aborts boot rather
// than silently degrading (no SQLite fallback, no in-memory identity).
func (c *Config) Validate() error {
	var missing []string
	if c.MySQL.DSN == "" {
		missing = append(missing, "mysql.dsn")
	}
	if c.Redis.Addr == "" {
		missing = append(missing, "redis.addr")
	}
	if c.HTTP.BasePath == "" || !strings.HasPrefix(c.HTTP.BasePath, "/") {
		return fmt.Errorf("http.base_path must be an absolute path, got %q", c.HTTP.BasePath)
	}
	if c.Worker.Concurrency < 1 {
		return fmt.Errorf("worker.concurrency must be >= 1, got %d", c.Worker.Concurrency)
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}
	return nil
}
