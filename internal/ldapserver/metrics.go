package ldapserver

// Metrics receives bounded-cardinality observations from the listener and
// dispatch paths (T-125). Labels are limited to operation names and RFC
// 4511 result codes by construction: no DN, attribute name or value,
// identity, or credential material ever crosses this interface, so a
// Metrics implementation cannot accidentally publish directory content.
type Metrics interface {
	// ObserveConnection is called with +1 when a client connection opens
	// and -1 when it closes.
	ObserveConnection(delta int)
	// ObserveOperation records one completed dispatch with the operation
	// name (for example "bind" or "search") and its result code.
	ObserveOperation(op string, code ResultCode)
}

// nopMetrics is the default when Options.Metrics is nil.
type nopMetrics struct{}

func (nopMetrics) ObserveConnection(int)               {}
func (nopMetrics) ObserveOperation(string, ResultCode) {}

func (s *Server) metrics() Metrics {
	if s.opts.Metrics == nil {
		return nopMetrics{}
	}
	return s.opts.Metrics
}
