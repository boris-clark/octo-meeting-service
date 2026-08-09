package config

import "testing"

func TestLoad_BindsEnv(t *testing.T) {
	t.Setenv("OCTO_MEETING_MYSQL__DSN", "u:p@tcp(localhost:3306)/db")
	t.Setenv("OCTO_MEETING_REDIS__ADDR", "localhost:6379")
	t.Setenv("OCTO_MEETING_WORKER__CONCURRENCY", "7")
	t.Setenv("OCTO_MEETING_CREDENTIAL__LOOKUP_SECRET", "ls")
	t.Setenv("OCTO_MEETING_CREDENTIAL__ENVELOPE_KEY", "ek")
	t.Setenv("OCTO_MEETING_PASSWORD__PEPPER", "pep")
	t.Setenv("OCTO_MEETING_PUBLIC_BASE_URL", "https://octo.example")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.MySQL.DSN != "u:p@tcp(localhost:3306)/db" {
		t.Fatalf("mysql.dsn not bound from env: %q", cfg.MySQL.DSN)
	}
	if cfg.Redis.Addr != "localhost:6379" {
		t.Fatalf("redis.addr not bound from env: %q", cfg.Redis.Addr)
	}
	if cfg.Worker.Concurrency != 7 {
		t.Fatalf("worker.concurrency not bound from env: %d", cfg.Worker.Concurrency)
	}
	if cfg.HTTP.BasePath != "/v1" {
		t.Fatalf("expected default base_path /v1, got %q", cfg.HTTP.BasePath)
	}
}

func TestLoad_MissingRequiredFails(t *testing.T) {
	// No DSN / Redis set -> must fail closed.
	if _, err := Load(); err == nil {
		t.Fatal("expected Load() to fail without required config")
	}
}

func baseValid() *Config {
	c := &Config{}
	c.HTTP.BasePath = "/v1"
	c.MySQL.DSN = "user:pass@tcp(localhost:3306)/octo_meeting"
	c.Redis.Addr = "localhost:6379"
	c.Worker.Concurrency = 4
	c.Credential.LookupSecret = "lookup-secret"
	c.Credential.EnvelopeKey = "envelope-secret"
	c.Password.Pepper = "pepper"
	c.PublicBaseURL = "https://octo.example"
	return c
}

func TestValidate_OK(t *testing.T) {
	if err := baseValid().Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestValidate_MissingDSN(t *testing.T) {
	c := baseValid()
	c.MySQL.DSN = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing mysql.dsn")
	}
}

func TestValidate_MissingRedis(t *testing.T) {
	c := baseValid()
	c.Redis.Addr = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing redis.addr")
	}
}

func TestValidate_BadBasePath(t *testing.T) {
	c := baseValid()
	c.HTTP.BasePath = "v1"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for relative base path")
	}
}

func TestValidate_BadConcurrency(t *testing.T) {
	c := baseValid()
	c.Worker.Concurrency = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for zero worker concurrency")
	}
}

func TestValidate_MissingEnvelopeKey(t *testing.T) {
	c := baseValid()
	c.Credential.EnvelopeKey = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing credential.envelope_key")
	}
}

func TestValidate_MissingLookupSecret(t *testing.T) {
	c := baseValid()
	c.Credential.LookupSecret = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing credential.lookup_secret")
	}
}

func TestValidate_MissingPepper(t *testing.T) {
	c := baseValid()
	c.Password.Pepper = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing password.pepper")
	}
}

func TestValidate_MissingPublicBaseURL(t *testing.T) {
	c := baseValid()
	c.PublicBaseURL = ""
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing public_base_url")
	}
}
