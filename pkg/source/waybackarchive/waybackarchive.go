package waybackarchive

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/projectdiscovery/tldfinder/pkg/session"
	"github.com/projectdiscovery/tldfinder/pkg/source"
	urlutil "github.com/projectdiscovery/utils/url"
)

type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
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

		resp, err := sess.SimpleGet(ctx, fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey", query))
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			sess.DiscardHTTPResponse(resp)
			return
		}

		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			line, _ = url.QueryUnescape(line)
			if parsed, err := urlutil.ParseURL(line, true); err == nil {
				domain := parsed.Hostname()
				results <- source.Result{Source: s.Name(), Type: source.Domain, Value: domain}
				s.results++
			}

			//leaving it here for future reference
			// for _, domain := range sess.Extractor.Extract(line) {
			// 	// fix for triple encoded URL
			// 	domain = strings.ToLower(domain)
			// 	domain = strings.TrimPrefix(domain, "25")
			// 	domain = strings.TrimPrefix(domain, "2f")

			// 	results <- source.Result{Source: s.Name(), Type: source.Domain, Value: domain}
			// 	s.results++
			// }
		}
	}()

	return results
}

func (s *Source) Name() string {
	return "waybackarchive"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) SupportedDiscoveryModes() []source.DiscoveryMode {
	return []source.DiscoveryMode{source.DNSMode}
}

func (s *Source) DiscoveryType() source.DiscoveryType {
	return source.Passive
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func (s *Source) Statistics() source.Statistics {
	return source.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
	}
}
