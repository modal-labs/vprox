package lib

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	connectCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "modal_vprox_connect_count",
	})
	disconnectCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "modal_vprox_disconnect_count",
	})
	connectLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "modal_vprox_connect_server_side_latency_ms",
		Buckets: []float64{1, 5, 10, 50, 100, 500, 1000, 5000, 10000},
	})
	disconnectLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "modal_vprox_disconnect_server_side_latency_ms",
		Buckets: []float64{1, 5, 10, 50, 100, 500, 1000, 5000},
	})
	wgConfigureLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "modal_vprox_wg_configure_latency_ms",
		Buckets: []float64{0.1, 0.5, 1, 5, 10, 50, 100, 500, 1000},
	}, []string{"operation"})
	activePeersGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "modal_vprox_active_peers",
	})
	allocatedIpsGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "modal_vprox_allocated_ips",
	})
)

// StartMetricsServer starts an HTTP server on :9090 serving Prometheus metrics.
// CPU and network bandwidth metrics are expected from the host-level Vector/DD agent.
func StartMetricsServer() {
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		log.Printf("metrics server listening on :9090")
		if err := http.ListenAndServe(":9090", mux); err != nil {
			log.Printf("metrics server failed: %v", err)
		}
	}()
}

func MetricsIncr(name string, tags ...string) {
	switch name {
	case "connect.count":
		connectCount.Inc()
	case "disconnect.count":
		disconnectCount.Inc()
	}
}

// MetricsTiming records a latency observation in milliseconds.
func MetricsTiming(name string, d time.Duration, tags ...string) {
	ms := float64(d.Microseconds()) / 1000.0
	switch name {
	case "connect.server_side_latency_ms":
		connectLatency.Observe(ms)
	case "disconnect.server_side_latency_ms":
		disconnectLatency.Observe(ms)
	case "wg_configure.latency_ms":
		operation := "unknown"
		for _, t := range tags {
			if k, v, ok := strings.Cut(t, ":"); ok && k == "operation" {
				operation = v
			}
		}
		wgConfigureLatency.WithLabelValues(operation).Observe(ms)
	}
}

func MetricsGauge(name string, value float64, tags ...string) {
	switch name {
	case "active_peers":
		activePeersGauge.Set(value)
	case "allocated_ips":
		allocatedIpsGauge.Set(value)
	}
}
