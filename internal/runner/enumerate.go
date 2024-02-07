package runner

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hako/durafmt"

	"github.com/projectdiscovery/gologger"

	"github.com/projectdiscovery/tldfinder/pkg/agent"
	"github.com/projectdiscovery/tldfinder/pkg/resolve"
	"github.com/projectdiscovery/tldfinder/pkg/source"
)

const maxNumCount = 2

// EnumerateSingleQuery wraps EnumerateSingleQuerynWithCtx with an empty context
func (r *Runner) EnumerateSingleQuery(query string, writers []io.Writer) error {
	return r.EnumerateSingleQueryWithCtx(context.Background(), query, writers)
}

// EnumerateSingleQueryWithCtx performs domain enumeration against a single query
func (r *Runner) EnumerateSingleQueryWithCtx(ctx context.Context, query string, writers []io.Writer) error {
	gologger.Info().Msgf("Enumerating domains for %s\n", query)

	// Check if the user has asked to remove wildcards explicitly.
	// If yes, create the resolution pool and get the wildcards for the current domain
	var resolutionPool *resolve.ResolutionPool
	if r.options.RemoveWildcard {
		resolutionPool = r.resolverClient.NewResolutionPool(r.options.Threads, r.options.RemoveWildcard)
		err := resolutionPool.InitWildcards(query)
		if err != nil {
			// Log the error but don't quit.
			gologger.Warning().Msgf("Could not get wildcards for domain %s: %s\n", query, err)
		}
	}

	// Run the domain enumeration
	now := time.Now()
	results := r.agent.EnumerateQueriesWithCtx(ctx, query, r.options.Proxy, r.options.RateLimit, r.options.Timeout, time.Duration(r.options.MaxEnumerationTime)*time.Minute, agent.WithCustomRateLimit(r.rateLimit))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	// Create a unique map for filtering duplicate domains out
	uniqueMap := make(map[string]resolve.HostEntry)
	// Create a map to track sources for each host
	sourceMap := make(map[string]map[string]struct{})
	// Process the results in a separate goroutine
	go func() {
		for result := range results {
			switch result.Type {
			case source.Error:
				gologger.Warning().Msgf("Could not run source %s: %s\n", result.Source, result.Error)
			case source.Domain:
				// Validate the domain found and remove wildcards from
				if r.options.DiscoveryMode == source.DNSMode && !strings.HasSuffix(result.Value, "."+query) {
					continue
				}

				domain := strings.ReplaceAll(strings.ToLower(result.Value), "*.", "")

				if matchDomain := r.filterAndMatchDomain(domain); matchDomain {
					if _, ok := uniqueMap[domain]; !ok {
						sourceMap[domain] = make(map[string]struct{})
					}

					// Log the verbose message about the found domain per source
					if _, ok := sourceMap[domain][result.Source]; !ok {
						gologger.Verbose().Label(result.Source).Msg(domain)
					}

					sourceMap[domain][result.Source] = struct{}{}

					// Check if the domain is a duplicate. If not,
					// send the domain for resolution.
					if _, ok := uniqueMap[domain]; ok {
						continue
					}

					hostEntry := resolve.HostEntry{Query: query, Host: domain, Source: result.Source}

					uniqueMap[domain] = hostEntry
					// If the user asked to remove wildcard then send on the resolve
					// queue. Otherwise, if mode is not verbose print the results on
					// the screen as they are discovered.
					if r.options.RemoveWildcard {
						resolutionPool.Tasks <- hostEntry
					}
				}
			}
		}
		// Close the task channel only if wildcards are asked to be removed
		if r.options.RemoveWildcard {
			close(resolutionPool.Tasks)
		}
		wg.Done()
	}()

	// If the user asked to remove wildcards, listen from the results
	// queue and write to the map. At the end, print the found results to the screen
	foundResults := make(map[string]resolve.Result)
	if r.options.RemoveWildcard {
		// Process the results coming from the resolutions pool
		for result := range resolutionPool.Results {
			switch result.Type {
			case resolve.Error:
				gologger.Warning().Msgf("Could not resolve host: %s\n", result.Error)
			case resolve.Subdomain:
				// Add the found domain to a map.
				if _, ok := foundResults[result.Host]; !ok {
					foundResults[result.Host] = result
				}
			}
		}
	}
	wg.Wait()
	outputWriter := NewOutputWriter(r.options.JSON)
	// Now output all results in output writers
	var err error
	for _, writer := range writers {
		if r.options.HostIP {
			err = outputWriter.WriteHostIP(query, foundResults, writer)
		} else {
			if r.options.RemoveWildcard {
				err = outputWriter.WriteHostNoWildcard(query, foundResults, writer)
			} else {
				if r.options.CaptureSources {
					err = outputWriter.WriteSourceHost(query, sourceMap, writer)
				} else {
					err = outputWriter.WriteHost(query, uniqueMap, writer)
				}
			}
		}
		if err != nil {
			gologger.Error().Msgf("Could not write results for %s: %s\n", query, err)
			return err
		}
	}

	// Show found domain count in any case.
	duration := durafmt.Parse(time.Since(now)).LimitFirstN(maxNumCount).String()
	var numberOfDomains int
	if r.options.RemoveWildcard {
		numberOfDomains = len(foundResults)
	} else {
		numberOfDomains = len(uniqueMap)
	}

	if r.options.ResultCallback != nil {
		if r.options.RemoveWildcard {
			for host, result := range foundResults {
				r.options.ResultCallback(&resolve.HostEntry{Query: host, Host: result.Host, Source: result.Source})
			}
		} else {
			for _, v := range uniqueMap {
				r.options.ResultCallback(&v)
			}
		}
	}
	gologger.Info().Msgf("Found %d domains for %s in %s\n", numberOfDomains, query, duration)

	if r.options.Statistics {
		gologger.Info().Msgf("Printing source statistics for %s", query)
		printStatistics(r.agent.GetStatistics())
	}

	return nil
}

func (r *Runner) filterAndMatchDomain(domain string) bool {
	if r.options.filterRegexes != nil {
		for _, filter := range r.options.filterRegexes {
			if m := filter.MatchString(domain); m {
				return false
			}
		}
	}
	if r.options.matchRegexes != nil {
		for _, match := range r.options.matchRegexes {
			if m := match.MatchString(domain); m {
				return true
			}
		}
		return false
	}
	return true
}
