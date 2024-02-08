package whoisxmlapi

import (
	"bytes"
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/tldfinder/pkg/session"
	"github.com/projectdiscovery/tldfinder/pkg/source"
	"github.com/projectdiscovery/tldfinder/pkg/utils"
)

type response struct {
	Search string `json:"search"`
	Result Result `json:"result"`
}

type Result struct {
	Count   int      `json:"count"`
	Records []Record `json:"records"`
}

type Record struct {
	Domain    string `json:"domain"`
	FirstSeen int    `json:"firstSeen"`
	LastSeen  int    `json:"lastSeen"`
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

		randomApiKey := utils.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		var nextPageSearchAfter string
		headers := map[string]string{"Content-Type": "application/json", "X-Authentication-Token": randomApiKey}

		for {
			requestBody := buildRequestBody(nextPageSearchAfter, query)
			fmt.Println(string(requestBody))
			resp, err := sess.Post(ctx, "https://reverse-whois.whoisxmlapi.com/api/v2", "",
				headers, bytes.NewReader(requestBody))

			if err != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
				s.errors++
				sess.DiscardHTTPResponse(resp)
				return
			}

			var data response
			err = jsoniter.NewDecoder(resp.Body).Decode(&data)
			if err != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
				s.errors++
				resp.Body.Close()
				return
			}

			resp.Body.Close()

			for _, record := range data.Result.Records {
				results <- source.Result{Source: s.Name(), Type: source.Domain, Value: record.Domain}
				s.results++
			}

			if nextPageSearchAfter == "" {
				break
			}
		}
	}()

	return results
}

func buildRequestBody(nextPageSearchAfter string, query string) []byte {
	var requestBody []byte
	if nextPageSearchAfter == "" {
		requestBody = []byte(fmt.Sprintf(`{
				"searchType": "current",
				"mode": "purchase",
				"punycode": true,
				"basicSearchTerms": {
					"include": ["%s"]
				}
			}`, query))
	} else {
		requestBody = []byte(fmt.Sprintf(`{
				"searchType": "current",
				"mode": "purchase",
				"punycode": true,
				"searchAfter": "%s",
				"basicSearchTerms": {
					"include": ["%s"]
				}
			}`, nextPageSearchAfter, query))
	}
	return requestBody
}

func (s *Source) Name() string {
	return "whoisxmlapi"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) SupportedDiscoveryModes() []source.DiscoveryMode {
	return []source.DiscoveryMode{source.DNSMode, source.DomainMode}
}

func (s *Source) DiscoveryType() source.DiscoveryType {
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
