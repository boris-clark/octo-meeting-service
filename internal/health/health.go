// Package health implements liveness and readiness checks.
package health

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Checker reports whether a single dependency is currently usable. Readiness
// aggregates all registered checkers; liveness never depends on them.
type Checker interface {
	// Name identifies the dependency in the readiness response.
	Name() string
	// Check returns nil when the dependency is ready.
	Check(ctx context.Context) error
}

// Registry holds the readiness checkers and the per-check timeout.
type Registry struct {
	mu       sync.RWMutex
	checkers []Checker
	timeout  time.Duration
}

// NewRegistry creates a readiness registry with the given per-check timeout.
func NewRegistry(timeout time.Duration) *Registry {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Registry{timeout: timeout}
}

// Register adds a dependency checker.
func (r *Registry) Register(c Checker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checkers = append(r.checkers, c)
}

// Liveness always reports OK: the process is running and the HTTP loop is
// serving. It must not touch external dependencies.
func (r *Registry) Liveness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Readiness runs every registered checker and returns 200 only if all pass,
// otherwise 503 with a per-dependency status map.
func (r *Registry) Readiness(c *gin.Context) {
	r.mu.RLock()
	checkers := make([]Checker, len(r.checkers))
	copy(checkers, r.checkers)
	timeout := r.timeout
	r.mu.RUnlock()

	results := make(map[string]string, len(checkers))
	ready := true
	for _, chk := range checkers {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		err := chk.Check(ctx)
		cancel()
		if err != nil {
			ready = false
			results[chk.Name()] = "unavailable"
			continue
		}
		results[chk.Name()] = "ok"
	}

	status := http.StatusOK
	overall := "ready"
	if !ready {
		status = http.StatusServiceUnavailable
		overall = "not_ready"
	}
	c.JSON(status, gin.H{"status": overall, "dependencies": results})
}
