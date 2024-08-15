package bufferover

import (
	"context"
	"fmt"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/tldfinder/pkg/session"
	"github.com/projectdiscovery/tldfinder/pkg/source"
	"github.com/projectdiscovery/tldfinder/pkg/utils"
)

type response struct {
	Meta struct {
		Errors []string `json:"Errors"`
	} `json:"Meta"`
	Results []string `json:"Results"`
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

		resp, err := sess.Get(ctx, fmt.Sprintf("https://tls.bufferover.run/dns?q=.%s", query), "",
			map[string]string{"x-api-key": randomApiKey})

		if err != nil && resp == nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			sess.DiscardHTTPResponse(resp)
			return
		}

		var bufforesponse response
		err = jsoniter.NewDecoder(resp.Body).Decode(&bufforesponse)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		metaErrors := bufforesponse.Meta.Errors

		if len(metaErrors) > 0 {
			results <- source.Result{
				Source: s.Name(), Type: source.Error, Error: fmt.Errorf("%s", strings.Join(metaErrors, ", ")),
			}
			s.errors++
			return
		}

		for _, result := range bufforesponse.Results {
			for _, value := range sess.Extractor.Extract(result) {
				results <- source.Result{Source: s.Name(), Type: source.Domain, Value: value}
			}
			s.results++
		}
	}()

	return results
}

func (s *Source) Name() string {
	return "bufferover"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) SupportedDiscoveryModes() []source.DiscoveryMode {
	return []source.DiscoveryMode{source.DNSMode}
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
