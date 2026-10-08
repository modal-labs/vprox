package lib

import (
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	connectCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "modal__vprox__connect__count",
	})
	disconnectCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "modal__vprox__disconnect__count",
	})
	connectLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "modal__vprox__connect__server_side_latency_ms",
		Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 25, 50, 100, 500, 1000, 5000, 10000},
	})
	disconnectLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "modal__vprox__disconnect__server_side_latency_ms",
		Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 25, 50, 100, 500, 1000, 5000},
	})
	wgConfigureLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "modal__vprox__wg_configure__latency_ms",
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 25, 50, 100, 500, 1000},
	}, []string{"operation"})
	activePeersGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "modal__vprox__active_peers",
	})
	allocatedIpsGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "modal__vprox__allocated_ips",
	})
)

// startMetricsServer serves Prometheus metrics over HTTP on port 9090 in a
// background goroutine. CPU and network bandwidth metrics are expected from
// the host-level Vector/DD agent.
func startMetricsServer() {
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		log.Printf("metrics server listening on :9090")
		if err := http.ListenAndServe(":9090", mux); err != nil {
			log.Printf("metrics server failed: %v", err)
		}
	}()
}

func recordConnectRequest() {
	connectCount.Inc()
}

func recordConnectLatency(duration time.Duration) {
	connectLatency.Observe(durationToMillis(duration))
}

func recordDisconnectRequest() {
	disconnectCount.Inc()
}

func recordDisconnectLatency(duration time.Duration) {
	disconnectLatency.Observe(durationToMillis(duration))
}

// recordWireguardConfigureLatency records how long one WireGuard device
// configuration call took, labeled by the kind of operation performed.
func recordWireguardConfigureLatency(operation string, duration time.Duration) {
	wgConfigureLatency.WithLabelValues(operation).Observe(durationToMillis(duration))
}

func setActivePeersGauge(activePeerCount int) {
	activePeersGauge.Set(float64(activePeerCount))
}

func setAllocatedIpsGauge(allocatedIpCount int) {
	allocatedIpsGauge.Set(float64(allocatedIpCount))
}

func durationToMillis(duration time.Duration) float64 {
	return float64(duration.Microseconds()) / 1000.0
}
