.PHONY: help build test scan ui clean check-deps

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

build: ## build the Go workers and the container
	go build -o bin/elfscan ./go/elfscan
	docker compose build

test: ## run the smoke test (proves the confirm/verify gate holds)
	python3 smoke_test.py

check-deps: ## show which extractors unblob still cannot find
	docker compose run --rm sentinel unblob --show-external-dependencies

scan: ## IMAGE=images/foo.bin SCOPE=REF-123 make scan
	@test -n "$(IMAGE)" || (echo "set IMAGE=images/<file>"; exit 1)
	@test -n "$(SCOPE)" || (echo "set SCOPE=<authorization ref>"; exit 1)
	docker compose run --rm sentinel \
	  python3 -m sentinel.cli firmware --image "$(IMAGE)" --scope "$(SCOPE)"

ui: ## serve the dashboard on 127.0.0.1:8089
	docker compose up sentinel

clean: ## drop extraction output, keep reports
	find runs -maxdepth 3 -name extracted -type d -exec rm -rf {} +
