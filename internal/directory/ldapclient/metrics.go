package ldapclient

import "time"

// Metrics receives pool events. Implementations must not record DNs or secrets.
type Metrics interface {
	OnDial(ok bool)
	OnAcquire(waited time.Duration)
	OnRelease()
	OnEvict(reason string)
	OnWaitTimeout()
}

type nopMetrics struct{}

func (nopMetrics) OnDial(bool)             {}
func (nopMetrics) OnAcquire(time.Duration) {}
func (nopMetrics) OnRelease()              {}
func (nopMetrics) OnEvict(string)          {}
func (nopMetrics) OnWaitTimeout()          {}

func metricsOf(m Metrics) Metrics {
	if m == nil {
		return nopMetrics{}
	}
	return m
}
