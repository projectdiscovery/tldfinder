package whoxy

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/tldfinder/pkg/session"
	"github.com/projectdiscovery/tldfinder/pkg/source"
	"github.com/projectdiscovery/tldfinder/pkg/utils"
)

type response struct {
	TotalPages   int `json:"total_pages"`
	CurrentPage  int `json:"current_page"`
	SearchResult []struct {
		DomainName string `json:"domain_name"`
	}
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
		page := 1
		for {
			resp, err := sess.Get(ctx, fmt.Sprintf("https://api.whoxy.com/?key=%s&reverse=whois&name=%s&page=%s", randomApiKey, query, page), "", nil)
			fmt.Print(resp)
			if err != nil && resp == nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
				s.errors++
				sess.DiscardHTTPResponse(resp)
				return
			}

			var whoxyResponse response
			err = jsoniter.NewDecoder(resp.Body).Decode(&whoxyResponse)
			if err != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
				s.errors++
				resp.Body.Close()
				return
			}

			resp.Body.Close()

			for _, result := range whoxyResponse.SearchResult {
				results <- source.Result{Source: s.Name(), Type: source.Domain, Value: result.DomainName}
				s.results++
			}

			if whoxyResponse.CurrentPage >= whoxyResponse.TotalPages {
				break
			}
			page++
		}

	}()

	return results
}

func (s *Source) Name() string {
	return "whoxy"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) SupportedDiscoveryModes() []source.DiscoveryMode {
	return []source.DiscoveryMode{source.DomainMode}
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

