.PHONY: test lint ci matrix install docker clean help

SHELL := /bin/bash
BATS  := $(shell command -v bats 2>/dev/null)
SC    := $(shell command -v shellcheck 2>/dev/null)

help:
	@echo "Targets:"
	@echo "  make test     — run all bats test cases"
	@echo "  make lint     — run shellcheck on all .sh files"
	@echo "  make ci       — lint + test (use in CI pipelines)"
	@echo "  make matrix   — run anzen in Debian/Ubuntu/Fedora/Rocky/Alpine/Arch/openSUSE containers"
	@echo "  make install  — install anzen system-wide (needs root)"
	@echo "  make docker   — build Docker image"
	@echo "  make clean    — remove generated reports"

test:
ifndef BATS
	$(error "bats not found — install with: sudo apt-get install bats")
endif
	@$(BATS) --tap tests/

lint:
ifndef SC
	$(error "shellcheck not found — install with: sudo apt-get install shellcheck")
endif
	@$(SC) -x -S warning \
		anzen.sh anzen-tui.sh install.sh \
		lib/*.sh \
		lib/checks/*.sh \
		lib/checks/runtimes/*.sh \
		macos/anzen-macos.sh tests/macos/check-ids.sh
	@echo "Lint complete."

ci: lint test

matrix:
	@tests/distro-matrix.sh
	@echo "CI checks passed."

install:
	@bash install.sh

docker:
	docker build -t anzen:latest .

clean:
	@rm -f reports/anzen_*.html reports/anzen_*.txt reports/anzen_*.json \
	        reports/remediate_*.sh
	@echo "Cleaned reports/"
