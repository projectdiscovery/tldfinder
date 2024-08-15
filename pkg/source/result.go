package source

type Result struct {
	Type   ResultType
	Source string
	Value  string
	Error  error
}

type ResultType int

const (
	Domain ResultType = iota
	Error
)
