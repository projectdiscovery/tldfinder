package runner

import (
	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
)

const banner = `
  __  __   ______         __       
 / /_/ /__/ / _(_)__  ___/ /__ ____
/ __/ / _  / _/ / _ \/ _  / -_) __/
\__/_/\_,_/_//_/_//_/\_,_/\__/_/   
`

// Name
const ToolName = `tldfinder`

// Version is the current version of tldfinder
const version = `v0.0.1`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// GetUpdateCallback returns a callback function that updates tldfinder
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("tldfinder", version)()
	}
}
