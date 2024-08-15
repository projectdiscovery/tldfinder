package runner

import (
	"bufio"
	"context"
	"io"
	"math"
	"net"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	contextutil "github.com/projectdiscovery/utils/context"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"

	"github.com/projectdiscovery/tldfinder/pkg/agent"
	"github.com/projectdiscovery/tldfinder/pkg/resolve"
)

// Runner is an instance of the domain enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options        *Options
	agent          *agent.Agent
	resolverClient *resolve.Resolver
	rateLimit      *agent.CustomRateLimit
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options}

	// Check if the application loading with any provider configuration, then take it
	// Otherwise load the default provider config
	if fileutil.FileExists(options.ProviderConfig) {
		gologger.Info().Msgf("Loading provider config from %s", options.ProviderConfig)
		options.loadProvidersFrom(options.ProviderConfig)
	} else {
		gologger.Info().Msgf("Loading provider config from the default location: %s", defaultProviderConfigLocation)
		options.loadProvidersFrom(defaultProviderConfigLocation)
	}

	// Initialize the domain enumeration engine
	runner.initializeAgent()

	// Initialize the domain resolver
	err := runner.initializeResolver()
	if err != nil {
		return nil, err
	}

	// Initialize the custom rate limit
	runner.rateLimit = &agent.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, uint]{
			Map: make(map[string]uint),
		},
	}

	for source, sourceRateLimit := range options.RateLimits.AsMap() {
		if sourceRateLimit.MaxCount > 0 && sourceRateLimit.MaxCount <= math.MaxUint {
			_ = runner.rateLimit.Custom.Set(source, sourceRateLimit.MaxCount)
		}
	}

	return runner, nil
}

func (r *Runner) initializeAgent() {
	r.agent = agent.New(r.options.Sources, r.options.ExcludeSources, r.options.All, r.options.DiscoveryMode)
}

func (r *Runner) initializeResolver() error {
	var resolvers []string

	// If the file has been provided, read resolvers from the file
	if r.options.ResolverList != "" {
		var err error
		resolvers, err = loadFromFile(r.options.ResolverList)
		if err != nil {
			return err
		}
	}

	if len(r.options.Resolvers) > 0 {
		resolvers = append(resolvers, r.options.Resolvers...)
	} else {
		resolvers = append(resolvers, resolve.DefaultResolvers...)
	}

	// Add default 53 UDP port if missing
	for i, resolver := range resolvers {
		if !strings.Contains(resolver, ":") {
			resolvers[i] = net.JoinHostPort(resolver, "53")
		}
	}

	r.resolverClient = resolve.New()
	var err error
	r.resolverClient.DNSClient, err = dnsx.New(dnsx.Options{BaseResolvers: resolvers, MaxRetries: 5})
	if err != nil {
		return nil
	}

	return nil
}

// RunEnumeration wraps RunEnumerationWithCtx with an empty context
func (r *Runner) RunEnumeration() error {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.RunEnumerationWithCtx(ctx)
}

// RunEnumerationWithCtx runs the domain enumeration flow on the targets specified
func (r *Runner) RunEnumerationWithCtx(ctx context.Context) error {
	outputs := []io.Writer{r.options.Output}

	if len(r.options.Domain) > 0 {
		domainsReader := strings.NewReader(strings.Join(r.options.Domain, "\n"))
		return r.EnumerateMultipleQueriesWithCtx(ctx, domainsReader, outputs)
	}

	// If we have STDIN input, treat it as multiple domains
	if r.options.Stdin {
		return r.EnumerateMultipleQueriesWithCtx(ctx, os.Stdin, outputs)
	}
	return nil
}

// EnumerateMultipleQueries wraps EnumerateMultipleDomainsWithCtx with an empty context
func (r *Runner) EnumerateMultipleQueries(reader io.Reader, writers []io.Writer) error {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.EnumerateMultipleQueriesWithCtx(ctx, reader, writers)
}

// EnumerateMultipleQueriesWithCtx enumerates domains for multiple queries
// We keep enumerating domains for a given query until we reach an error
func (r *Runner) EnumerateMultipleQueriesWithCtx(ctx context.Context, reader io.Reader, writers []io.Writer) error {
	scanner := bufio.NewScanner(reader)
	ip, _ := regexp.Compile(`^([0-9\.]+$)`)
	for scanner.Scan() {
		domain, err := normalizeLowercase(scanner.Text())
		isIp := ip.MatchString(domain)
		if errors.Is(err, ErrEmptyInput) || (r.options.ExcludeIps && isIp) {
			continue
		}

		var file *os.File
		// If the user has specified an output file, use that output file instead
		// of creating a new output file for each domain. Else create a new file
		// for each domain in the directory.
		if r.options.OutputFile != "" {
			outputWriter := NewOutputWriter(r.options.JSON)
			file, err = outputWriter.createFile(r.options.OutputFile, true)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
				return err
			}

			err = r.EnumerateSingleQueryWithCtx(ctx, domain, append(writers, file))

			file.Close()
		} else if r.options.OutputDirectory != "" {
			outputFile := path.Join(r.options.OutputDirectory, domain)
			if r.options.JSON {
				outputFile += ".json"
			} else {
				outputFile += ".txt"
			}

			outputWriter := NewOutputWriter(r.options.JSON)
			file, err = outputWriter.createFile(outputFile, false)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
				return err
			}

			err = r.EnumerateSingleQueryWithCtx(ctx, domain, append(writers, file))

			file.Close()
		} else {
			err = r.EnumerateSingleQueryWithCtx(ctx, domain, writers)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
