package http

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics encapsulates Prometheus collectors for the proxy.
type Metrics struct {
	reg                     *prometheus.Registry
	ChallengesTotal         *prometheus.CounterVec
	ActiveRecords           prometheus.GaugeFunc
	CloudflareRequestsTotal *prometheus.CounterVec
	RequestDuration         *prometheus.HistogramVec
}

// NewMetrics initializes and registers proxy metrics.
// If reg is nil, a dedicated registry is created.
func NewMetrics(reg *prometheus.Registry, activeRecordsFunc func() float64) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}

	m := &Metrics{
		reg: reg,
		ChallengesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "acme_dns_challenges_total",
				Help: "Total number of ACME DNS challenges processed, partitioned by status and client.",
			},
			[]string{"status", "client"},
		),
		CloudflareRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "acme_dns_cloudflare_requests_total",
				Help: "Total number of outgoing requests to Cloudflare API, partitioned by endpoint and status.",
			},
			[]string{"endpoint", "status"},
		),
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "acme_dns_request_duration_seconds",
				Help:    "Histogram of request processing duration in seconds, partitioned by handler and status.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"handler", "status"},
		),
	}

	reg.MustRegister(m.ChallengesTotal)
	reg.MustRegister(m.CloudflareRequestsTotal)
	reg.MustRegister(m.RequestDuration)

	if activeRecordsFunc != nil {
		m.ActiveRecords = prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "acme_dns_active_records",
				Help: "Current count of active ACME DNS TXT challenge records tracked in memory.",
			},
			activeRecordsFunc,
		)
		reg.MustRegister(m.ActiveRecords)
	}

	return m
}

// Registry returns the underlying prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.reg
}

// ObserveCloudflareRequest implements cloudflare.Observer.
func (m *Metrics) ObserveCloudflareRequest(endpoint, status string) {
	if m != nil && m.CloudflareRequestsTotal != nil {
		m.CloudflareRequestsTotal.WithLabelValues(endpoint, status).Inc()
	}
}
