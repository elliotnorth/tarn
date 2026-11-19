package certs

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Set answers TLS handshakes from one or more Managers. During an
// apply-then-confirm change it holds the new one first and the old one after.
type Set struct {
	list atomic.Pointer[[]*Manager]
}

// Replace sets the Managers, most preferred first.
func (s *Set) Replace(ms ...*Manager) { s.list.Store(&ms) }

// GetCertificate is for tls.Config.
func (s *Set) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p := s.list.Load()
	if p == nil {
		return nil, errors.New("no certificate yet")
	}
	name := ""
	if hello != nil {
		name = strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	}
	var fallback *tls.Certificate
	for _, m := range *p {
		c := m.cur.Load()
		if c == nil {
			continue
		}
		if name != "" && strings.HasSuffix(name, "."+m.cfg.Zone) {
			return c, nil
		}
		if fallback == nil {
			fallback = c
		}
	}
	if fallback == nil {
		return nil, errors.New("no certificate yet")
	}
	return fallback, nil
}

// Tarn's own limits, inside Let's Encrypt's: 5 certificates a week for one name
// and 5 failed validations an hour. Certificates issued before this ledger
// existed aren't in it, so the weekly limit leaves one spare.
const (
	maxIssuedPerWeek   = 4
	maxAttemptsPerHour = 5
	week               = 7 * 24 * time.Hour
)

type ledgerEntry struct {
	T  time.Time `json:"t"`
	OK bool      `json:"ok"`
}

// The ledger is shared by every Manager using the same directory.
var ledgerMu sync.Mutex

func (m *Manager) ledgerPath() string { return filepath.Join(m.root, "issuance.json") }

func (m *Manager) readLedger() map[string][]ledgerEntry {
	out := map[string][]ledgerEntry{}
	if b, err := os.ReadFile(m.ledgerPath()); err == nil {
		json.Unmarshal(b, &out) // a damaged ledger must not block renewals
	}
	return out
}

func recent(es []ledgerEntry, now time.Time, d time.Duration, okOnly bool) int {
	n := 0
	for _, e := range es {
		if now.Sub(e.T) < d && (e.OK || !okOnly) {
			n++
		}
	}
	return n
}

// reserveIssue checks the limits and records an attempt. Every certificate
// request goes through here, so no path can issue in a loop.
func (m *Manager) reserveIssue(now time.Time) error {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	l := m.readLedger()
	es := l[m.Domain()]
	if recent(es, now, week, true) >= maxIssuedPerWeek {
		return fmt.Errorf("refusing to request another certificate for %s: %d were issued in the last 7 days, and Let's Encrypt allows 5", m.Domain(), maxIssuedPerWeek)
	}
	if recent(es, now, time.Hour, false) >= maxAttemptsPerHour {
		return fmt.Errorf("refusing to request another certificate for %s: %d attempts in the last hour", m.Domain(), maxAttemptsPerHour)
	}
	kept := es[:0:0]
	for _, e := range es {
		if now.Sub(e.T) < week {
			kept = append(kept, e)
		}
	}
	l[m.Domain()] = append(kept, ledgerEntry{T: now})
	return m.writeLedger(l)
}

func (m *Manager) markIssued() {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	l := m.readLedger()
	if es := l[m.Domain()]; len(es) > 0 {
		es[len(es)-1].OK = true
		m.writeLedger(l)
	}
}

func (m *Manager) writeLedger(l map[string][]ledgerEntry) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return writeFile(m.ledgerPath(), b)
}

// IssuedThisWeek says how many certificates this ledger has seen for the name.
func (m *Manager) IssuedThisWeek(now time.Time) int {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	return recent(m.readLedger()[m.Domain()], now, week, true)
}

// WillIssue reports whether Ensure would request a new certificate, ignoring
// ARI: a usable stored one means it wouldn't.
func (m *Manager) WillIssue(now time.Time) bool {
	cert, err := m.load()
	return err != nil || needsIssue(cert.Leaf, m.Domain(), now)
}

// Ready reports whether a certificate is loaded.
func (m *Manager) Ready() bool { return m.cur.Load() != nil }

// SetEmail changes the ACME contact, sent on the next certificate request.
func (m *Manager) SetEmail(email string) {
	m.mu.Lock()
	m.email = email
	m.mu.Unlock()
}

func (m *Manager) contact() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.email
}

// migrateLegacy copies a certificate from the old one-zone layout. It copies
// rather than moves, so going back to an older tarn doesn't cost a certificate.
func (m *Manager) migrateLegacy() {
	if _, err := os.Stat(filepath.Join(m.dir, "cert.pem")); err == nil {
		return
	}
	certPEM, err1 := os.ReadFile(filepath.Join(m.root, "cert.pem"))
	keyPEM, err2 := os.ReadFile(filepath.Join(m.root, "key.pem"))
	if err1 != nil || err2 != nil {
		return
	}
	pair, err := parsePair(certPEM, keyPEM)
	if err != nil || needsIssueForName(pair.Leaf, m.Domain()) {
		return
	}
	writeFile(filepath.Join(m.dir, "key.pem"), keyPEM)
	writeFile(filepath.Join(m.dir, "cert.pem"), certPEM)
}
