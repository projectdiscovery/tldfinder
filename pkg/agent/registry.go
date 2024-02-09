package agent

import (
	"github.com/projectdiscovery/tldfinder/pkg/source"
	"github.com/projectdiscovery/tldfinder/pkg/source/bufferover"
	"github.com/projectdiscovery/tldfinder/pkg/source/censys"
	"github.com/projectdiscovery/tldfinder/pkg/source/crtsh"
	"github.com/projectdiscovery/tldfinder/pkg/source/dnsrepo"
	dnsxSrc "github.com/projectdiscovery/tldfinder/pkg/source/dnsx"
	"github.com/projectdiscovery/tldfinder/pkg/source/netlas"
	"github.com/projectdiscovery/tldfinder/pkg/source/waybackarchive"
	"github.com/projectdiscovery/tldfinder/pkg/source/whoisxmlapi"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var AllSources = map[string]source.Source{
	"bufferover":     &bufferover.Source{},
	"censys":         &censys.Source{},
	"dnsrepo":        &dnsrepo.Source{},
	"netlas":         &netlas.Source{},
	"waybackarchive": &waybackarchive.Source{},
	"whoisxmlapi":    &whoisxmlapi.Source{},
	"crtsh":          &crtsh.Source{},
	"dnsx":           &dnsxSrc.Source{},
}

var sourceWarnings = mapsutil.NewSyncLockMap[string, string](
	mapsutil.WithMap(mapsutil.Map[string, string]{
		"passivetotal": "New API credentials for PassiveTotal can't be generated, but existing user account credentials are still functional. Please ensure your integrations are using valid credentials.",
	}))
