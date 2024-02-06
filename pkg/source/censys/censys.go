package censys

import (
	"context"
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/tldfinder/pkg/session"
	"github.com/projectdiscovery/tldfinder/pkg/source"
	"github.com/projectdiscovery/tldfinder/pkg/utils"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	maxCensysPages = 10
	maxPerPage     = 100
)

type response struct {
	Code   int    `json:"code"`
	Status string `json:"status"`
	Result result `json:"result"`
}

type result struct {
	Query      string  `json:"query"`
	Total      float64 `json:"total"`
	DurationMS int     `json:"duration_ms"`
	Hits       []hit   `json:"hits"`
	Links      links   `json:"links"`
}

type hit struct {
	Parsed            parsed   `json:"parsed"`
	Names             []string `json:"names"`
	FingerprintSha256 string   `json:"fingerprint_sha256"`
}

type parsed struct {
	ValidityPeriod validityPeriod `json:"validity_period"`
	SubjectDN      string         `json:"subject_dn"`
	IssuerDN       string         `json:"issuer_dn"`
}

type validityPeriod struct {
	NotAfter  string `json:"not_after"`
	NotBefore string `json:"not_before"`
}

type links struct {
	Next string `json:"next"`
	Prev string `json:"prev"`
}

type Source struct {
	apiKeys   []apiKey
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

type apiKey struct {
	token  string
	secret string
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

		randomApiKey := utils.PickRandom(s.apiKeys, s.Name())
		if randomApiKey.token == "" || randomApiKey.secret == "" {
			s.skipped = true
			return
		}

		certSearchEndpoint := "https://search.censys.io/api/v2/certificates/search"
		cursor := ""
		currentPage := 1
		for {
			certSearchEndpointUrl, err := urlutil.Parse(certSearchEndpoint)
			if err != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
				s.errors++
				return
			}

			certSearchEndpointUrl.Params.Add("q", query)
			certSearchEndpointUrl.Params.Add("per_page", strconv.Itoa(maxPerPage))
			if cursor != "" {
				certSearchEndpointUrl.Params.Add("cursor", cursor)
			}

			resp, err := sess.HTTPRequest(
				ctx,
				"GET",
				certSearchEndpointUrl.String(),
				"",
				nil,
				nil,
				session.BasicAuth{Username: randomApiKey.token, Password: randomApiKey.secret},
			)

			if err != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
				s.errors++
				sess.DiscardHTTPResponse(resp)
				return
			}

			var censysResponse response
			err = jsoniter.NewDecoder(resp.Body).Decode(&censysResponse)
			if err != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
				s.errors++
				resp.Body.Close()
				return
			}

			resp.Body.Close()

			for _, hit := range censysResponse.Result.Hits {
				for _, name := range hit.Names {
					results <- source.Result{Source: s.Name(), Type: source.Domain, Value: name}
					s.results++
				}
			}

			cursor = censysResponse.Result.Links.Next
			if cursor == "" || currentPage >= maxCensysPages {
				break
			}
			currentPage++
		}
	}()

	return results
}

func (s *Source) Name() string {
	return "censys"
}

func (s *Source) IsDefault() bool {
	return true
}

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
	s.apiKeys = utils.CreateApiKeys(keys, func(k, v string) apiKey {
		return apiKey{k, v}
	})
}

func (s *Source) Statistics() source.Statistics {
	return source.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
