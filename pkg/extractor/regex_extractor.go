package extractor

import (
	"regexp"
	"strings"
)

// RegexDomainExtractor is a concrete implementation of the DomainExtractor interface, using regex for extraction.
type RegexDomainExtractor struct {
	extractor *regexp.Regexp
}

// NewRegexDomainExtractor creates a new regular expression to extract domains
func NewRegexDomainExtractor() (*RegexDomainExtractor, error) {
	extractor, err := regexp.Compile(`(?m)\b(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b`)
	if err != nil {
		return nil, err
	}
	return &RegexDomainExtractor{extractor: extractor}, nil
}

// Extract implements the DomainExtractor interface, using the regex to find domains in the given text.
func (re *RegexDomainExtractor) Extract(text string) []string {
	matches := re.extractor.FindAllString(text, -1)
	for i, match := range matches {
		matches[i] = strings.ToLower(match)
	}
	return matches
}
