package config

import "testing"

func TestLoad_BindsEnv(t *testing.T) {
	t.Setenv("OCTO_MEETING_MYSQL__DSN", "u:p@tcp(localhost:3306)/db")
	t.Setenv("OCTO_MEETING_REDIS__ADDR", "localhost:6379")
	t.Setenv("OCTO_MEETING_WORKER__CONCURRENCY", "7")

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
