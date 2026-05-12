# CI-side provenance generation.
#
# Run `make provenance` at build time (e.g. inside your CI image build job).
# The output `provenance.json` is consumed by the agent at startup via
# `agent.yaml`'s `provenance.file` field.
#
# In production set `provenance.required: true` in agent.yaml so the agent
# refuses to start if this file is missing or fields are blank.

SHELL := /bin/bash

# Override these in CI: they are the four facts CI knows that the
# application does not.
CODE_HASH ?= sha256:$(shell git rev-parse HEAD 2>/dev/null || echo unknown)
POLICY_BUNDLE_HASH ?= sha256:$(shell sha256sum agent.yaml 2>/dev/null | cut -d' ' -f1 || echo unknown)
MODEL_HASH ?= sha256:unknown
BUILD_ARTIFACT_REF ?= local-dev

.PHONY: provenance
provenance:
	@printf '%s\n' \
	  '{' \
	  '  "code_hash": "$(CODE_HASH)",' \
	  '  "policy_bundle_hash": "$(POLICY_BUNDLE_HASH)",' \
	  '  "model_hash": "$(MODEL_HASH)",' \
	  '  "build_artifact_ref": "$(BUILD_ARTIFACT_REF)"' \
	  '}' > provenance.json
	@echo "wrote provenance.json:"
	@cat provenance.json

.PHONY: clean
clean:
	rm -f provenance.json
