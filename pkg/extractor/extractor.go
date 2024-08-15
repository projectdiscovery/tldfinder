package extractor

// DomainExtractor is an interface that defines the contract for domain extraction.
type DomainExtractor interface {
	Extract(text string) []string
}
