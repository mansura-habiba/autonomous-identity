# Thin wrapper around scripts/demo.sh — run `make help`
.PHONY: help clean install install-a2a demo-minimal demo-delegate demo-langchain demo-swap demo-langgraph demo-mcp demo-a2a-server demo-a2a-client demo-all

help:
	@./scripts/demo.sh help

clean:
	@./scripts/demo.sh clean

install:
	@./scripts/demo.sh install

install-a2a:
	@./scripts/demo.sh install-a2a

demo-minimal:
	@./scripts/demo.sh run minimal

demo-delegate:
	@./scripts/demo.sh run delegate

demo-langchain:
	@./scripts/demo.sh run langchain

demo-swap:
	@./scripts/demo.sh run swap

demo-langgraph:
	@./scripts/demo.sh run langgraph

demo-mcp:
	@./scripts/demo.sh run mcp

demo-a2a-server:
	@./scripts/demo.sh run a2a-server

demo-a2a-client:
	@./scripts/demo.sh run a2a-client

demo-all:
	@./scripts/demo.sh run all

fresh-langgraph: clean install demo-langgraph
