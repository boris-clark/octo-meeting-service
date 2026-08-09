package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the service's Prometheus collectors. Bootstrap ships only
// baseline HTTP metrics; domain collectors are added later.
type Metrics struct {
	registry     *prometheus.Registry
	HTTPRequests *prometheus.CounterVec
	HTTPDuration *prometheus.HistogramVec
	BuildInfo    *prometheus.GaugeVec
}

// NewMetrics constructs and registers the baseline collectors.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())

	m := &Metrics{
		registry: reg,
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests by method, route, and status.",
		}, []string{"method", "route", "status"}),
		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency by method and route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "build_info",
			Help: "Build metadata; value is always 1.",
		}, []string{"version", "commit"}),
	}
	reg.MustRegister(m.HTTPRequests, m.HTTPDuration, m.BuildInfo)
	return m
}

// Handler exposes the metrics endpoint for the dedicated metrics listener.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// SetBuildInfo records the running build's version and commit.
func (m *Metrics) SetBuildInfo(version, commit string) {
	m.BuildInfo.WithLabelValues(version, commit).Set(1)
}
