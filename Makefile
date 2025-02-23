.DEFAULT_GOAL := help

LOCAL_BIN=$(CURDIR)/bin

GOENV:=GOPRIVATE=""

.PHONY: test
test: ## run tests in project
	$(GOENV) go test ./...


.PHONY: build
build: ## build project
	$(GOENV) go build -o $(LOCAL_BIN)/reader ./main.go

.PHONY: download
download: ## dowmload deps
	$(GOENV) go mod download

.PHONY: tidy
tidy: ## check deps
	$(GOENV) go mod tidy

.PHONY: help
help:
	@grep --no-filename -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'