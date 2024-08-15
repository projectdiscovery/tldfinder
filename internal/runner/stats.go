package runner

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tldfinder/pkg/source"
	"golang.org/x/exp/maps"
)

func printStatistics(stats map[string]source.Statistics) {

	sources := maps.Keys(stats)
	sort.Strings(sources)

	var lines []string
	var skipped []string

	for _, source := range sources {
		sourceStats := stats[source]
		if sourceStats.Skipped {
			skipped = append(skipped, fmt.Sprintf(" %s", source))
		} else {
			lines = append(lines, fmt.Sprintf(" %-20s %-10s %10d %10d", source, sourceStats.TimeTaken.Round(time.Millisecond).String(), sourceStats.Results, sourceStats.Errors))
		}
	}

	if len(lines) > 0 {
		gologger.Print().Msgf("\n Source               Duration      Results     Errors\n%s\n", strings.Repeat("─", 56))
		gologger.Print().Msgf("%s\n", strings.Join(lines, "\n"))
	}

	if len(skipped) > 0 {
		gologger.Print().Msgf("\n The following sources were included but skipped...\n\n")
		gologger.Print().Msgf("%s\n\n", strings.Join(skipped, "\n"))
	}
}
