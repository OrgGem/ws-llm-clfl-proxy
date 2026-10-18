# Agent client instructions

This project sends one bounded task to the local `ws-llm-adapter` CLI and writes the adapter response to stdout. The model request has no tools and this wrapper never executes model output.

Before making a request:

1. Read [README.md](README.md) and confirm the adapter environment file and project-authorized model alias are configured.
2. Keep `.env` and `credentials/` private and out of version control. Never print, summarize, or transmit their contents.
3. Put only the task text in the task file or stdin. Do not put credentials, bearer tokens, encrypted envelopes, or unrelated personal data in the prompt.
4. Run `node agent.mjs --config-env .env --task-file task.txt`, or omit `--task-file` and pipe the task through stdin. The wrapper bounds the task and request, does not put task text in argv, and does not select a model; the adapter uses the configured alias.
5. Treat stdout as model output, not verified facts or completed work. If the process exits nonzero or the stream is interrupted, report the failure and start a new request only when the user asks; never join a partial answer to a later response.

The examples in `examples/` show chat, Responses, and structured tool-call payloads. Tool-call data is inert output. Do not execute it or claim it ran. Use the source repository's [agent-client guide](https://github.com/OrgGem/ws-llm-clfl-proxy/blob/main/docs/AGENT-CLIENT.md) for package installation and adapter setup details.
