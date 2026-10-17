# Plan

A Rust tool that lets an AI agent fetch websites in a **controlled** way (HTTP GET),
with security as the starting point: no access to the internal network, a configurable
denylist and hard limits on size and time.

---

## 1. Goal and scope

**In scope (v0.1)**
- HTTP `GET` (and `HEAD`) to http and https URLs
- Two output modes:
  - **Markdown** (default): HTML → Markdown, JSON pretty-printed, so an LLM can read it well
  - **Raw**: the response **byte-exact** as the server sends it, without conversion
- Optionally **save the exact response to a file**
- Request headers supplied by the AI
- Security policy via a config file (denylist, limits)
- Two ways to use it:
  1. **MCP server (stdio)**: so Claude Code, Claude Desktop and other AI clients can call it as a tool
  2. **CLI**: `surfshield get <url>` for manual testing and scripting

**Out of scope (later)**
- Multipart uploads, cookie jar/sessions
  (POST, PUT, PATCH and DELETE have been added: MCP tools `post_url`, `put_url`, `patch_url`,
  `delete_url` and the CLI subcommands of the same name, see README)
- Rendering JavaScript (headless browser)
- Caching, rate limiting, audit logging

---

## 2. Architecture

```
surfshield/
├── Cargo.toml
├── surfshield.example.toml        # example config
├── src/
│   ├── main.rs                  # CLI entry point (clap): `get`, `head`, `serve`
│   ├── config.rs                # load + validate config (TOML, serde)
│   ├── policy.rs                # URL, IP and header checks (denylist, SSRF protection)
│   ├── fetch.rs                 # HTTP client (reqwest), redirects, limits
│   ├── output.rs                # markdown/raw rendering, charset, truncation, saving to file
│   ├── mcp.rs                   # MCP server over stdio (JSON-RPC)
│   ├── error.rs                 # error types (thiserror)
│   └── lib.rs
└── tests/
    ├── fetch_tests.rs           # against a local mock server (wiremock)
    └── mcp_tests.rs             # end-to-end MCP over stdio of the binary
                                 # (policy unit tests are in src/policy.rs)
```

**Flow of one request**

```
AI → MCP tool call "fetch_url" → policy check (scheme, denylist, port, headers)
   → DNS resolution → IP check (no private/loopback/link-local)
   → GET with timeout and max. bytes → policy and IP check again on every redirect
   → format = markdown: convert + truncate
     format = raw:      exact body unchanged (or save to file)
   → result back to the AI
```

---

## 3. Downloading exact HTML (raw mode)

For cases where the AI needs the HTML (or other content) **exactly**:

| Option | Behaviour |
|---|---|
| `format: "raw"` | The body is returned **unchanged**: no conversion, no cleanup, no whitespace changes. As text if it is valid UTF-8; otherwise as base64 with `encoding: "base64"`, so no byte is lost |
| `save_to: "<path>"` | The exact bytes are written to a file. The AI then only gets metadata back (path, size, content type, SHA-256). This also works for a large page that does not fit in the LLM context. Only `max_body_bytes` applies then, not `max_output_chars` |
| Truncation in raw | If an inline raw body is larger than `max_output_chars`, it is cut off with `truncated: true` and a hint to use `save_to`. A file is never truncated |

**Safety of `save_to`**: only within a configured `download_dir`
(default `./surfshield-downloads`). No absolute paths or `..` outside it, and existing
files are not overwritten unless `overwrite: true`.

CLI equivalent:
```bash
surfshield get https://example.com --raw
```
```bash
surfshield get https://example.com -o page.html
```

---

## 4. Security measures

Starting point: **everything is allowed, except what is on the denylist**. Protection of
the internal network does stay active by default.

| Risk | Measure |
|---|---|
| Unwanted sites | **Domain denylist** (exact + wildcard `*.example.com`). Empty = everything allowed |
| SSRF to the internal network / cloud metadata (`169.254.169.254`) | Check the IP after DNS resolution. Blocked: loopback, private (RFC1918), link-local, CGNAT, multicast, IPv6 ULA. The connection goes to the **checked IP** (prevents DNS rebinding). Can be disabled with `allow_private_ips = true` for local development |
| Redirect to a forbidden target | Follow redirects manually (max. 5), every hop through the policy again |
| Huge responses | Max. body size (default 10 MB), read as a stream and abort |
| Hanging connections | Connect timeout (5s) and total timeout (30s) |
| Odd schemes (`file://`, `ftp://`) | Only `http` and `https` |
| Odd ports | All ports allowed, except those on a configurable `denied_ports` list (default empty) |
| Header abuse | See section 5 |
| Prompt injection via a web page | In markdown mode the output is marked as *untrusted external content* |

---

## 5. Request headers from the AI

The AI can pass a `headers` object (e.g. `Accept`, `Accept-Language`, `User-Agent`, `Authorization`).

- **Always refused** (protocol or security sensitive): `Host`, `Content-Length`,
  `Transfer-Encoding`, `Connection`, `Upgrade`, `TE`, `Proxy-*`. Can be overridden via
  `denied_request_headers` in the config.
- **On a redirect to another domain**, `Authorization` and `Cookie` are stripped
  (as browsers do), so credentials do not leak to a third party.
- Validation of header names and values (no CR/LF injection), max. 50 headers and max. 8 KB in total.
- If `User-Agent` is not supplied, the default from the config is used.

---

## 6. Configuration (example)

```toml
[policy]
denied_domains    = ["*.internal.example.com"]
allowed_schemes   = ["http", "https"]
denied_ports      = []
allow_private_ips = false
denied_request_headers = ["host", "content-length", "transfer-encoding",
                          "connection", "upgrade", "te", "proxy-*"]

[limits]
max_body_bytes       = 10_000_000
max_output_chars     = 100_000
connect_timeout_secs = 5
total_timeout_secs   = 30
max_redirects        = 5

[http]
user_agent = "surfshield/0.1"

[download]
download_dir = "./surfshield-downloads"
```

Location: `--config <path>`, otherwise `./surfshield.toml`, otherwise `~/.config/surfshield/config.toml`.
Without a config file the defaults above apply.

---

## 7. MCP tools the AI gets

| Tool | Parameters | Result |
|---|---|---|
| `fetch_url` | `url`, `format` (`markdown` \| `raw`, default `markdown`), `headers` (optional), `max_chars` (optional, ≤ config), `save_to` (optional), `overwrite` (optional) | status, final URL, response headers, content type, body (or file metadata), `truncated`, `encoding` |
| `head_url` | `url`, `headers` (optional) | status, response headers, final URL |

Registration in Claude Code, for example:
```bash
claude mcp add surfshield -- /path/to/surfshield serve --config ~/.config/surfshield/config.toml
```

CLI options: `--raw`, `-o/--output <file>`, `-H "Name: value"` (repeatable, like curl),
`--include` (show response headers), `--config`.

---

## 8. Dependencies

| Crate | Purpose |
|---|---|
| `tokio` | async runtime |
| `reqwest` (rustls, no native-tls, `stream`) | HTTP client |
| `rmcp` (official Rust MCP SDK) | MCP server over stdio |
| `clap` | CLI |
| `serde`, `toml`, `serde_json` | config / JSON |
| `url`, `ipnet` | URL parsing, IP ranges |
| `htmd` | HTML → Markdown (strip `<script>`/`<style>`) |
| `base64`, `sha2` | raw mode for binary content, checksum when saving |
| `thiserror`, `anyhow`, `tracing` | errors and logging (logging to **stderr**; stdout is for MCP) |
| dev: `wiremock`, `tempfile` | tests against a local mock server |

---

## 9. Implementation steps

1. **Skeleton**: `cargo new`, dependencies, clap subcommands, config loading + example config
2. **Policy**: URL validation, denylist with wildcards, IP classification, header validation + unit tests
3. **Fetch**: reqwest client with its own DNS resolver that checks IPs, manual redirects (with header stripping), timeouts, streaming size limit
4. **Output**: markdown conversion + truncation; raw mode (exact bytes, UTF-8/base64), `save_to` with path validation and SHA-256
5. **CLI**: `get` / `head` with `--raw`, `-o`, `-H`, `--include`
6. **MCP server**: `surfshield serve` with `fetch_url` and `head_url`
7. **Tests**: integration tests with wiremock on localhost, including:
   - raw output is byte-identical to what the server sends (also for binary and non-UTF-8)
   - a redirect to a private IP or denylisted domain is refused
   - `Authorization` is stripped on a cross-domain redirect
   - a too-large body, a timeout, and `save_to` with `..` are refused
8. **Docs**: README with installation, config, CLI examples and MCP registration
9. **Quality**: `cargo clippy -D warnings`, `cargo fmt`

Testing only happens against a local mock server (localhost); during the build
no requests are made to external sites.
