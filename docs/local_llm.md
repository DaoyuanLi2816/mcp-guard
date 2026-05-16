# Optional local-LLM judge

`mcp-fence` is local-first. The core scanner, fuzzer, sandbox, and
report generator do not need any LLM. The **optional** semantic judge
adds a "is this tool description suspicious?" classifier that runs
*entirely against a local endpoint*.

## What it adds

- A second opinion on tool descriptions, name, and schema. Useful when
  the deterministic rules don't trigger but the description still
  smells of poisoning.
- Adds findings under `MCPG010` with `source: "llm-judge"` so reports
  show which findings came from the model and which from regex rules.

## What it doesn't do

- It does not replace deterministic detection.
- It does not talk to any cloud LLM. No content from your scan leaves
  the host.
- A failure to reach the local LLM is *silent*: the core scan still
  finishes and exits cleanly.

## Backends

Two flavours are supported out of the box:

1. **Ollama** (`--llm-judge ollama`, default). Targets
   `http://localhost:11434/api/chat`.
2. **OpenAI-compatible** (`--llm-judge openai-compatible`). Targets the
   `/chat/completions` route on any local OpenAI-compatible server
   (vLLM, LM Studio, llama.cpp's `llama-server`, …).

Override the endpoint and model with `--llm-endpoint` and `--llm-model`.

## Recommended models for an RTX 4080 (16 GB VRAM)

- `qwen3:8b` — good default. Fits comfortably; <2 s judgements.
- `qwen3:14b` — better judgements; uses most of the VRAM. Set
  `--llm-timeout` higher (default 15 s) if your first request is cold.
- `llama3.1:8b-instruct-q5_K_M` — fine alternative.

The default model name is read from `MCP_GUARD_LLM_MODEL` and falls
back to `qwen3:8b`.

## Example

```bash
# Make sure ollama is running and the model is pulled.
ollama pull qwen3:8b
ollama serve            # usually started by the desktop client

# Run a scan with the judge enabled.
mcp-fence scan examples/vulnerable_metadata_server/mcp.json \
    --inspect --llm-judge ollama --model qwen3:8b
```

For a local vLLM server:

```bash
mcp-fence scan examples/vulnerable_metadata_server/mcp.json \
    --inspect \
    --llm-judge openai-compatible \
    --llm-endpoint http://localhost:8000/v1 \
    --llm-model qwen3:8b
```

## Prompt

The judge uses a fixed system prompt (no user-controllable content)
asking the model to return a single line of JSON:

```json
{"suspicious": true|false, "score": 0..1, "reason": "<one short sentence>"}
```

Anything else in the response is ignored. The judge tolerates models
that wrap JSON in a code fence.

## Safety

- The judge does not run shell commands or read host files.
- It never includes secrets in the prompt; it sees only the tool name,
  description, and input schema.
- The endpoint must be a local URL. There is no built-in path to a
  cloud provider.
