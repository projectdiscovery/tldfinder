package registry

import (
	_ "embed"
	"strings"

	"github.com/projectdiscovery/tldfinder/pkg/utils"
)

//go:embed tlds.txt
var tldData string

//go:embed private_tlds.txt
var privateTldData string

var (
	TLDs        = processTLDData(tldData)
	PrivateTLDs = processTLDData(privateTldData)
)

func processTLDData(data string) []string {
	lines := strings.Split(data, "\n")
	for i, line := range lines {
		lines[i], _ = utils.Sanitize(line)
	}
	return lines
}
