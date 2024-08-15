# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v 
LDFLAGS := -s -w

ifneq ($(shell go env GOOS),darwin)
LDFLAGS := -extldflags "-static"
endif
    
all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "tldfinder" cmd/tldfinder/main.go
test: 
	$(GOTEST) $(GOFLAGS) ./...
tidy:
	$(GOMOD) tidy
verify: tidy
	$(GOMOD) verify