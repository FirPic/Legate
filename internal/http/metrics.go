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
	DNSRequestsTotal        *prometheus.CounterVec
	RequestDuration         *prometheus.HistogramVec
}

// NewMetrics initializes and registers proxy metrics.
// Note: In accordance with security audit VULN-02, client identifiers are omitted to prevent user enumeration.
func NewMetrics(reg *prometheus.Registry, activeRecordsFunc func() float64) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}

	m := &Metrics{
		reg: reg,
		ChallengesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "acme_dns_challenges_total",
				Help: "Total number of ACME DNS challenges processed, partitioned by status.",
			},
			[]string{"status"},
		),
		CloudflareRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "acme_dns_cloudflare_requests_total",
				Help: "Total number of outgoing requests to Cloudflare API, partitioned by endpoint and status.",
			},
			[]string{"endpoint", "status"},
		),
		DNSRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "acme_dns_provider_requests_total",
				Help: "Total number of outgoing requests to upstream DNS providers, partitioned by provider, endpoint and status.",
			},
			[]string{"provider", "endpoint", "status"},
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
	reg.MustRegister(m.DNSRequestsTotal)
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
	if m != nil {
		if m.CloudflareRequestsTotal != nil {
			m.CloudflareRequestsTotal.WithLabelValues(endpoint, status).Inc()
		}
		if m.DNSRequestsTotal != nil {
			m.DNSRequestsTotal.WithLabelValues("cloudflare", endpoint, status).Inc()
		}
	}
}

// ObserveDNSRequest implements generic observer for multi-provider metric collection (IONOS, Infomaniak, etc.).
func (m *Metrics) ObserveDNSRequest(providerName, endpoint, status string) {
	if m != nil && m.DNSRequestsTotal != nil {
		m.DNSRequestsTotal.WithLabelValues(providerName, endpoint, status).Inc()
	}
}
