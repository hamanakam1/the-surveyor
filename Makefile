.PHONY: help test scan demo verify validate sample schema conformance screenshots clean

PY ?= python3
export PYTHONPATH := src

help:
	@echo "make test        run the suite (no dependencies beyond pytest)"
	@echo "make scan        survey this machine and print the ASCII plat"
	@echo "make demo        survey into a throwaway ledger and narrate the first change"
	@echo "make verify      check the local ledger's hash chain"
	@echo "make validate    validate examples/sample.oet.json"
	@echo "make sample      regenerate examples/sample.oet.json"
	@echo "make schema      regenerate schema/oet-1.0.schema.json from the model"
	@echo "make conformance regenerate the broken-plat corpus"
	@echo "make screenshots regenerate docs/screenshots/*.png (needs pillow)"
	@echo "make clean       remove caches"

test:
	$(PY) -m pytest

scan:
	$(PY) -m surveyor scan --ascii

demo:
	rm -rf /tmp/surveyor-demo
	$(PY) -m surveyor --store /tmp/surveyor-demo --site demo scan --ascii
	$(PY) -m surveyor --store /tmp/surveyor-demo --site demo scan --quiet
	$(PY) -m surveyor --store /tmp/surveyor-demo diff --format markdown | head -40

verify:
	$(PY) -m surveyor verify

validate:
	@tmp=$$(mktemp -d); $(PY) -m surveyor --store $$tmp scan --scanners host --no-save --output /tmp/_surveyor_check.json >/dev/null && \
	$(PY) -m surveyor validate /tmp/_surveyor_check.json && \
	$(PY) -m surveyor validate examples/sample.oet.json

sample:
	$(PY) scripts/make_sample.py

schema:
	$(PY) scripts/make_schema.py

conformance:
	$(PY) scripts/make_conformance.py

screenshots:
	$(PY) scripts/make_screenshots.py

clean:
	rm -rf .pytest_cache src/**/__pycache__ tests/__pycache__ build dist *.egg-info
