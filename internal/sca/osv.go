package sca

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	osvVulnURL  = "https://api.osv.dev/v1/vulns/"
)

type Client struct {
	http      *http.Client
	userAgent string
	cache     map[string]*osvRecord
}

func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	return &Client{
		http:      &http.Client{Timeout: timeout},
		userAgent: "vibecheck/0.1 (+https://github.com/NotChaosuu/vibecheck)",
		cache:     map[string]*osvRecord{},
	}
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvRecord struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package osvPackage `json:"package"`
		Ranges  []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func (c *Client) queryBatch(ctx context.Context, deps []Dependency) ([][]string, error) {
	out := make([][]string, len(deps))
	const chunk = 1000
	for start := 0; start < len(deps); start += chunk {
		end := start + chunk
		if end > len(deps) {
			end = len(deps)
		}
		queries := make([]osvQuery, 0, end-start)
		for _, d := range deps[start:end] {
			queries = append(queries, osvQuery{
				Package: osvPackage{Name: d.Name, Ecosystem: d.Ecosystem},
				Version: d.Version,
			})
		}
		body, _ := json.Marshal(map[string]any{"queries": queries})

		req, err := http.NewRequestWithContext(ctx, "POST", osvBatchURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", c.userAgent)

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		var parsed osvBatchResponse
		derr := json.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("osv querybatch returned %d", resp.StatusCode)
		}
		if derr != nil {
			return nil, derr
		}
		for i, r := range parsed.Results {
			if start+i >= len(out) {
				break
			}
			for _, v := range r.Vulns {
				out[start+i] = append(out[start+i], v.ID)
			}
		}
	}
	return out, nil
}

func (c *Client) getVuln(ctx context.Context, id string) (*osvRecord, error) {
	if rec, ok := c.cache[id]; ok {
		return rec, nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET", osvVulnURL+id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv vuln %s returned %d", id, resp.StatusCode)
	}
	var rec osvRecord
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		return nil, err
	}
	c.cache[id] = &rec
	return &rec, nil
}

func (r *osvRecord) fixedVersion(pkgName string) string {
	for _, a := range r.Affected {
		if !strings.EqualFold(a.Package.Name, pkgName) {
			continue
		}
		for _, rg := range a.Ranges {
			for _, e := range rg.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func (r *osvRecord) primaryURL() string {
	for _, ref := range r.References {
		if ref.Type == "ADVISORY" {
			return ref.URL
		}
	}
	if len(r.References) > 0 {
		return r.References[0].URL
	}
	return ""
}
