package lib

import (
	"log"
	"os"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
)

var metrics *statsd.Client

// InitMetrics initializes the DogStatsD client. Metrics are sent via UDP to
// localhost:8125 where a Vector/DD agent picks them up. If the agent isn't
// running, UDP sends silently fail — no impact on the server.
//
// CPU and network bandwidth metrics are expected to come from the host-level
// Vector/DD agent (host_metrics source), not from this process.
func InitMetrics() {
	hostname, _ := os.Hostname()
	var err error
	metrics, err = statsd.New("127.0.0.1:8125",
		statsd.WithNamespace("modal.vprox."),
		statsd.WithTags([]string{"node:" + hostname}),
	)
	if err != nil {
		log.Printf("failed to init statsd client: %v (metrics disabled)", err)
	}
}

func MetricsIncr(name string, tags ...string) {
	if metrics != nil {
		metrics.Incr(name, tags, 1)
	}
}

func MetricsTiming(name string, d time.Duration, tags ...string) {
	if metrics != nil {
		metrics.Timing(name, d, tags, 1)
	}
}

func MetricsGauge(name string, value float64, tags ...string) {
	if metrics != nil {
		metrics.Gauge(name, value, tags, 1)
	}
}
