package certs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Cloudflare checks what the API token can do, so a zone change is refused
// before it costs a certificate attempt.
type Cloudflare struct {
	Token   string
	BaseURL string // defaults to the real API; set in tests
	Client  *http.Client
}

type cfResponse struct {
	Success bool                       `json:"success"`
	Errors  []struct{ Message string } `json:"errors"`
	Result  json.RawMessage            `json:"result"`
}

func (c *Cloudflare) do(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	base := c.BaseURL
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("can't reach Cloudflare")
	}
	defer resp.Body.Close()
	var out cfResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("unreadable answer from Cloudflare (HTTP %d)", resp.StatusCode)
	}
	if !out.Success {
		if len(out.Errors) > 0 {
			return nil, errors.New(out.Errors[0].Message)
		}
		return nil, fmt.Errorf("Cloudflare answered HTTP %d", resp.StatusCode)
	}
	return out.Result, nil
}

// Verify reports whether the token is valid and active.
func (c *Cloudflare) Verify(ctx context.Context) error {
	res, err := c.do(ctx, http.MethodGet, "/user/tokens/verify", nil)
	if err != nil {
		return err
	}
	var v struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(res, &v); err != nil {
		return err
	}
	if v.Status != "active" {
		return fmt.Errorf("the token is %s", v.Status)
	}
	return nil
}

// CheckZone proves the token can edit DNS for zone, by creating and deleting a
// harmless TXT record: Cloudflare has no dry run, and issuance needs exactly
// this permission.
func (c *Cloudflare) CheckZone(ctx context.Context, zone string) error {
	id, err := c.findZone(ctx, zone)
	if err != nil {
		return err
	}
	res, err := c.do(ctx, http.MethodPost, "/zones/"+id+"/dns_records", map[string]any{
		"type": "TXT", "name": "_tarn-check." + zone, "content": "tarn permission check", "ttl": 60,
	})
	if err != nil {
		return fmt.Errorf("the Cloudflare token can't edit DNS for %s: %w", zone, err)
	}
	var rec struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res, &rec); err != nil || rec.ID == "" {
		return errors.New("unreadable answer from Cloudflare")
	}
	if _, err := c.do(ctx, http.MethodDelete, "/zones/"+id+"/dns_records/"+rec.ID, nil); err != nil {
		return fmt.Errorf("the check record _tarn-check.%s couldn't be deleted: %w", zone, err)
	}
	return nil
}

// findZone walks up the labels until Cloudflare knows the name.
func (c *Cloudflare) findZone(ctx context.Context, zone string) (string, error) {
	for name := zone; strings.Contains(name, "."); name = name[strings.IndexByte(name, '.')+1:] {
		res, err := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(name), nil)
		if err != nil {
			return "", fmt.Errorf("Cloudflare refused the zone lookup: %w", err)
		}
		var zones []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(res, &zones); err != nil {
			return "", errors.New("unreadable answer from Cloudflare")
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("the Cloudflare token can't see any zone covering %s", zone)
}
