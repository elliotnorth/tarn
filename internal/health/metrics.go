package health

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"
)

// metrics serves the same totals as /healthz in Prometheus text format. Like
// /healthz it is open on loopback and needs sign-in through the proxy, and
// like the DNS stats it holds totals only: no device names, no client IPs.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if !s.Metrics {
		http.NotFound(w, r)
		return
	}
	if viaProxy(r) && !s.authorized(w, r) {
		return
	}

	var b bytes.Buffer
	m := func(name, kind, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}
	stamp := func(t *time.Time) float64 {
		if t == nil || t.IsZero() {
			return 0
		}
		return float64(t.UnixNano()) / 1e9
	}

	m("tarn_build_info", "gauge", "Always 1; the version is a label.")
	fmt.Fprintf(&b, "tarn_build_info{version=%q} 1\n", s.Version)

	h := s.Store.Health()
	idx := s.Store.Load()
	m("tarn_records", "gauge", "Names in the current record index.")
	fmt.Fprintf(&b, "tarn_records %d\n", idx.Len())
	m("tarn_peer_refresh_last_success_timestamp_seconds", "gauge", "Last successful peer list refresh, 0 if none yet.")
	fmt.Fprintf(&b, "tarn_peer_refresh_last_success_timestamp_seconds %g\n", stamp(&h.LastOK))
	m("tarn_peer_refresh_consecutive_failures", "gauge", "Peer list refreshes that have failed in a row.")
	fmt.Fprintf(&b, "tarn_peer_refresh_consecutive_failures %d\n", h.ConsecutiveFails)
	up := 0
	if idx != nil && s.now().Sub(h.LastOK) <= 3*s.interval() {
		up = 1
	}
	m("tarn_peer_data_fresh", "gauge", "1 when /healthz would say ok, 0 when starting or stale.")
	fmt.Fprintf(&b, "tarn_peer_data_fresh %d\n", up)

	if s.DNS != nil {
		if counts, ok := s.DNS().(map[string]uint64); ok {
			keys := make([]string, 0, len(counts))
			for k := range counts {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			m("tarn_dns_replies_total", "counter", "DNS replies by outcome since tarn started.")
			for _, k := range keys {
				fmt.Fprintf(&b, "tarn_dns_replies_total{outcome=%q} %d\n", k, counts[k])
			}
		}
	}

	if s.TLS != nil {
		// The certificate state is the /healthz JSON, read back by field
		// name so this package needn't import the ACME code.
		var c struct {
			Staging          bool       `json:"staging"`
			NotAfter         *time.Time `json:"not_after"`
			RenewBy          *time.Time `json:"renew_by"`
			LastRenewed      *time.Time `json:"last_renewed"`
			ConsecutiveFails int        `json:"consecutive_failures"`
		}
		if raw, err := json.Marshal(s.TLS()); err == nil && json.Unmarshal(raw, &c) == nil {
			staging := 0
			if c.Staging {
				staging = 1
			}
			m("tarn_cert_not_after_timestamp_seconds", "gauge", "When the current certificate expires, 0 if there is none.")
			fmt.Fprintf(&b, "tarn_cert_not_after_timestamp_seconds %g\n", stamp(c.NotAfter))
			m("tarn_cert_renew_by_timestamp_seconds", "gauge", "Two thirds of the certificate's lifetime; ARI may renew earlier.")
			fmt.Fprintf(&b, "tarn_cert_renew_by_timestamp_seconds %g\n", stamp(c.RenewBy))
			m("tarn_cert_last_renewed_timestamp_seconds", "gauge", "Last unattended renewal, 0 if none yet.")
			fmt.Fprintf(&b, "tarn_cert_last_renewed_timestamp_seconds %g\n", stamp(c.LastRenewed))
			m("tarn_cert_consecutive_failures", "gauge", "Issuance or renewal attempts that have failed in a row.")
			fmt.Fprintf(&b, "tarn_cert_consecutive_failures %d\n", c.ConsecutiveFails)
			m("tarn_cert_staging", "gauge", "1 when the certificate is from the untrusted staging service.")
			fmt.Fprintf(&b, "tarn_cert_staging %d\n", staging)
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b.Bytes())
}
