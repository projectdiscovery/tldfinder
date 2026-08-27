package runner

import (
	"github.com/pkg/errors"

	"github.com/projectdiscovery/tldfinder/pkg/utils"
	fileutil "github.com/projectdiscovery/utils/file"
)

func loadFromFile(file string) ([]string, error) {
	var items []string
	for item, err := range fileutil.Lines(file) {
		if err != nil {
			return nil, err
		}
		item, err = utils.Sanitize(item)
		if errors.Is(err, utils.ErrEmptyInput) {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}
