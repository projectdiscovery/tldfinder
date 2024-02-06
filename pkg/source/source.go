package source

import (
	"context"

	"github.com/projectdiscovery/tldfinder/pkg/session"
)

// Source is an interface inherited by each passive source
type Source interface {
	// Run takes a query as argument and a session object
	// which contains the extractor for domain, http client
	// and other stuff.
	Run(context.Context, string, *session.Session) <-chan Result

	// Name returns the name of the source. It is preferred to use lower case names.
	Name() string

	// IsDefault returns true if the current source should be
	// used as part of the default execution.
	IsDefault() bool

	SupportedModes() []DiscoveryMode

	EnumerationType() EnumerationType

	// NeedsKey returns true if the source requires an API key
	NeedsKey() bool

	AddApiKeys([]string)

	// Statistics returns the scrapping statistics for the source
	Statistics() Statistics
}

type DiscoveryMode uint8

const (
	DNSMode DiscoveryMode = iota
	TLDMode
	DomainMode
)

func (dm DiscoveryMode) String() string {
	return [...]string{"dns", "tld", "domain"}[dm]
}

type EnumerationType uint8

const (
	Active EnumerationType = iota
	Passive
)
