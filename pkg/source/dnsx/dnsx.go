package dnsrepo

import (
	"context"
	"math"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/tldfinder/pkg/registry"
	"github.com/projectdiscovery/tldfinder/pkg/session"
	"github.com/projectdiscovery/tldfinder/pkg/source"
)

// Using data from data.iana.org/TLD/tlds-alpha-by-domain.txt as the source for TLDs

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

		dnsxOptions := dnsx.DefaultOptions
		dnsxOptions.MaxRetries = 2
		dnsxOptions.TraceMaxRecursion = math.MaxInt16
		dnsxOptions.QuestionTypes = []uint16{dns.TypeA}
		dnsX, err := dnsx.New(dnsxOptions)
		if err != nil {
			results <- source.Result{Source: s.Name(), Type: source.Error, Error: err}
			s.errors++
			return
		}

		var domains []string
		for _, tld := range registry.TLDs {
			domains = append(domains, query+"."+tld)
		}
		for _, domain := range domains {
			sourceName := ctx.Value(session.CtxSourceArg).(string)
			mrlErr := sess.MultiRateLimiter.Take(sourceName)
			if mrlErr != nil {
				results <- source.Result{Source: s.Name(), Type: source.Error, Error: mrlErr}
				s.errors++
				return
			}
			dnsData := dnsx.ResponseData{}
			dnsData.DNSData, _ = dnsX.QueryMultiple(domain)
			if dnsData.DNSData == nil || dnsData.DNSData.StatusCode == "NXDOMAIN" || dnsData.Host == "" || dnsData.Timestamp.IsZero() {
				continue
			}

			results <- source.Result{Source: s.Name(), Type: source.Domain, Value: domain}
			s.results++
		}
	}()

	return results
}

func (s *Source) Name() string {
	return "dnsx"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) SupportedDiscoveryModes() []source.DiscoveryMode {
	return []source.DiscoveryMode{source.TLDMode}
}

func (s *Source) DiscoveryType() source.DiscoveryType {
	return source.Active
}

func (s *Source) NeedsKey() bool {
	return false
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
