package runner

import (
	"github.com/pkg/errors"

	"github.com/projectdiscovery/tldfinder/pkg/utils"
	fileutil "github.com/projectdiscovery/utils/file"
)

func loadFromFile(file string) ([]string, error) {
	chanItems, err := fileutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var items []string
	for item := range chanItems {
		var err error
		item, err = utils.Sanitize(item)
		if errors.Is(err, utils.ErrEmptyInput) {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}
