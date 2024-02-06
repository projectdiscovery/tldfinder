package netlas

import (
	"context"
	"io"

	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/projectdiscovery/tldfinder/pkg/session"
	"github.com/projectdiscovery/tldfinder/pkg/source"
	"github.com/projectdiscovery/tldfinder/pkg/utils"
)

type Item struct {
	Data struct {
		A           []string `json:"a,omitempty"`
		Txt         []string `json:"txt,omitempty"`
		LastUpdated string   `json:"last_updated,omitempty"`
		Timestamp   string   `json:"@timestamp,omitempty"`
		Ns          []string `json:"ns,omitempty"`
		Level       int      `json:"level,omitempty"`
		Zone        string   `json:"zone,omitempty"`
		Domain      string   `json:"domain,omitempty"`
		Cname       []string `json:"cname,omitempty"`
		Mx          []string `json:"mx,omitempty"`
	} `json:"data"`
}

type DomainsResponse struct {
	Items []Item `json:"items"`
	Took  int    `json:"took"`
}

type DomainsCountResponse struct {
	Count int `json:"count"`
}

type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

func (s *Source) Run(ctx context.Context, query string, sess *session.Session) <-chan source.Result {
	results := make(chan source.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		// To get count of domains
		endpoint := "https://app.netlas.io/api/domains_count/"
		params := url.Values{}
		query := fmt.Sprintf("domain:*.%s", query)
		params.Set("q", query)
		countUrl := endpoint + "?" + params.Encode()

		randomApiKey := utils.PickRandom(s.apiKeys, s.Name())
		resp, err := sess.HTTPRequest(ctx, http.MethodGet, countUrl, "", map[string]string{
			"accept":    "application/json",
			"X-API-Key": randomApiKey,
		}, nil, session.BasicAuth{})

		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			return
		} else if resp.StatusCode != 200 {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: fmt.Errorf("request rate limited with status code %d", resp.StatusCode)}
			s.errors++
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: fmt.Errorf("error reading ressponse body")}
			s.errors++
			return
		}

		var domainsCount DomainsCountResponse
		err = json.Unmarshal(body, &domainsCount)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			return
		}

		for i := 0; i < domainsCount.Count; i += 20 {
			offset := strconv.Itoa(i)

			endpoint := "https://app.netlas.io/api/domains/"
			params := url.Values{}
			params.Set("q", query)
			params.Set("source_type", "include")
			params.Set("start", offset)
			params.Set("fields", "*")
			apiUrl := endpoint + "?" + params.Encode()

			randomApiKey := utils.PickRandom(s.apiKeys, s.Name())

			resp, err := sess.HTTPRequest(ctx, http.MethodGet, apiUrl, "", map[string]string{
				"accept":    "application/json",
				"X-API-Key": randomApiKey}, nil, session.BasicAuth{})
			if err != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
				s.errors++
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: fmt.Errorf("error reading ressponse body")}
				s.errors++
				return
			}

			if resp.StatusCode == 429 {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: fmt.Errorf("request rate limited with status code %d", resp.StatusCode)}
				s.errors++
				break
			}

			var data DomainsResponse
			err = json.Unmarshal(body, &data)
			if err != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
				s.errors++
				return
			}

			for _, item := range data.Items {
				results <- source.Result{
					Source: s.Name(), Type: source.Domain, Value: item.Data.Domain,
				}
				s.results++
			}
		}

	}()

	return results
}

func (s *Source) Name() string {
	return "netlas"
}

func (s *Source) IsDefault() bool {
	return false
}

// TODO: add support for TLD; search for Paypal domains in every TLDs: domain:paypal.* level:2
func (s *Source) SupportedModes() []source.DiscoveryMode {
	return []source.DiscoveryMode{source.DNSMode}
}

func (s *Source) EnumerationType() source.EnumerationType {
	return source.Passive
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() source.Statistics {
	return source.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
