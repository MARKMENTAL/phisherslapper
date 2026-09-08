// Package rdap queries RDAP registration data via https://rdap.org/domain/.
// Mirrors bash rdap_query / get_registration_date / get_registrar.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Event is a single RDAP event object.
type Event struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

// entity is the minimal shape needed for registrar extraction.
type entity struct {
	Roles      []string          `json:"roles"`
	VCardArray []json.RawMessage `json:"vcardArray"`
}

// Response is the minimal RDAP payload we parse.
type Response struct {
	Events   []Event  `json:"events"`
	Entities []entity `json:"entities"`
}

// Result bundles the parsed response with the raw JSON (for --verbose).
type Result struct {
	Raw   []byte
	Resp  *Response
	Found bool
}

// Query fetches RDAP JSON for domain with retries (mirrors bash MAX_ATTEMPTS=3).
func Query(ctx context.Context, client *http.Client, domain string, perCall time.Duration) (*Result, error) {
	const maxAttempts = 3
	var lastErr error
	url := "https://rdap.org/domain/" + domain
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		r, err := queryOnce(ctx, client, url, perCall)
		if err == nil {
			return r, nil
		}
		lastErr = err
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
	return nil, lastErr
}

func queryOnce(ctx context.Context, client *http.Client, url string, perCall time.Duration) (*Result, error) {
	callCtx, cancel := context.WithTimeout(ctx, perCall)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("RDAP %s: status %s", url, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var parsed Response
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("RDAP %s: invalid JSON: %w", url, err)
	}
	return &Result{Raw: raw, Resp: &parsed, Found: true}, nil
}

// RegistrationDate returns YYYY-MM-DD of the registration event,
// or "Unknown / Lookup Failed" (mirrors bash get_registration_date).
func RegistrationDate(r *Result) string {
	if r == nil || !r.Found || r.Resp == nil {
		return "Unknown / Lookup Failed"
	}
	for _, e := range r.Resp.Events {
		if e.Action == "registration" && e.Date != "" {
			if len(e.Date) >= 10 {
				return e.Date[:10]
			}
			return e.Date
		}
	}
	return "Unknown / Lookup Failed"
}

// Registrar returns the best-effort registrar name, or "Unknown".
// Prefers entities with the registrar role, falling back to the first vCard fn.
func Registrar(r *Result) string {
	if r == nil || !r.Found || r.Resp == nil {
		return "Unknown"
	}
	// First pass: registrar role.
	for _, e := range r.Resp.Entities {
		if hasRole(e.Roles, "registrar") {
			if name := vcardFN(e.VCardArray); name != "" {
				return name
			}
		}
	}
	// Second pass: any entity fn.
	for _, e := range r.Resp.Entities {
		if name := vcardFN(e.VCardArray); name != "" {
			return name
		}
	}
	return "Unknown"
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// vcardFN extracts the "fn" property from a vcardArray value.
// vcardArray shape: ["vcard", [["fn", {}, "text", "Name"], ...]]
func vcardFN(vcard []json.RawMessage) string {
	if len(vcard) < 2 {
		return ""
	}
	var props []json.RawMessage
	if err := json.Unmarshal(vcard[1], &props); err != nil {
		return ""
	}
	for _, p := range props {
		var arr []json.RawMessage
		if err := json.Unmarshal(p, &arr); err != nil || len(arr) < 4 {
			continue
		}
		var key string
		if err := json.Unmarshal(arr[0], &key); err != nil || key != "fn" {
			continue
		}
		var name string
		if err := json.Unmarshal(arr[3], &name); err != nil {
			continue
		}
		if strings.TrimSpace(name) != "" {
			return name
		}
	}
	return ""
}
