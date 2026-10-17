# surfshield: controlled web access for AI agents

A Rust tool that accesses websites over HTTP GET/HEAD/POST/PUT/PATCH/DELETE
under a security policy, usable as an **MCP server** (for Claude Code, Claude Desktop
and other MCP clients) or as a **CLI**.

## Install

With [Homebrew](https://brew.sh):

```bash
brew install dnovitski/tap/surfshield
```

This installs the prebuilt binary from the [latest release](https://github.com/dnovitski/surfshield/releases/latest)
(Apple Silicon), so no Rust toolchain or access to crates.io is needed. An example config is then in
`$(brew --prefix)/share/surfshield/surfshield.example.toml`. To update, run `brew upgrade surfshield`.

Or from source:

```bash
cargo install --path .
```

## Use as an MCP server

```bash
claude mcp add surfshield -- surfshield serve
```

With your own config:

```bash
claude mcp add surfshield -- surfshield serve --config /path/to/surfshield.toml
```

### Tools

**`fetch_url`**: HTTP GET.

| Parameter | Description |
|---|---|
| `url` | http(s) URL |
| `format` | `markdown` (default): HTML → Markdown, JSON pretty-printed. `raw`: the body **exactly** as received (base64 if it is not valid UTF-8) |
| `headers` | Extra request headers, e.g. `{"Accept": "application/json"}` |
| `max_chars` | Max. number of body characters (capped by `max_output_chars`) |
| `save_to` | Save the exact body to this path, relative to `download_dir`. Only metadata is returned (path, bytes, SHA-256) |
| `overwrite` | Replace an existing file at `save_to` |

The result consists of a JSON block with metadata (status, final URL, redirects, response headers,
truncation) and, except with `save_to`, a second block with the body. In markdown mode the body is
wrapped in `<<<BEGIN/END UNTRUSTED EXTERNAL CONTENT>>>` markers; in raw mode it is unchanged.

**`post_url`**, **`put_url`**, **`patch_url`**, **`delete_url`**: HTTP POST, PUT, PATCH and DELETE.
These tools change state on the remote site (forms, API calls, deletions). They are separate tools,
so you can choose per method in your MCP client whether to ask for confirmation.

| Parameter | Description |
|---|---|
| `url` | http(s) URL |
| `body` | Raw body, sent exactly (default `Content-Type: text/plain; charset=utf-8`) |
| `json` | JSON body, sent with `Content-Type: application/json` |
| `form` | Form fields, URL-encoded with `Content-Type: application/x-www-form-urlencoded` |
| `headers`, `format`, `max_chars`, `save_to`, `overwrite` | As with `fetch_url` |

At most one of `body`, `json` and `form`. Without a body, POST, PUT and PATCH send an empty body
(`Content-Length: 0`) and DELETE sends none. A `Content-Type` in `headers` overrides the default. The result has the same shape as with `fetch_url`.

**`head_url`**: HTTP HEAD; returns status, final URL and response headers.

## Use as a CLI

```bash
surfshield get https://example.com
```
```bash
surfshield get --raw https://example.com > page.html
```
```bash
surfshield get -o page.html https://example.com
```
```bash
surfshield get -i -H "Accept: application/json" https://api.example.com/data
```
```bash
surfshield head https://example.com
```
```bash
surfshield post --json '{"name": "test"}' https://api.example.com/items
```
```bash
surfshield post --field q=searchterm --field lang=en https://example.com/search
```
```bash
surfshield post -d @body.xml -H "Content-Type: application/xml" https://example.com/api
```
```bash
surfshield put --json @item.json https://api.example.com/items/7
```
```bash
surfshield patch --json '{"status": "done"}' https://api.example.com/items/7
```
```bash
surfshield delete https://api.example.com/items/7
```

- `--raw` writes the exact bytes to stdout.
- `-o FILE` writes the exact bytes to any path (like curl); the `download_dir` restriction
  only applies to MCP `save_to`.
- `post`, `put`, `patch` and `delete` take at most one body: `-d/--data` (sent exactly, `@FILE` or `@-` for stdin; default
  `Content-Type: application/x-www-form-urlencoded` like curl), `--json` (also `@FILE`/`@-`, is
  validated) or `--field NAME=VALUE` (repeatable, URL-encoded). `--raw`, `-o`, `-H`, `-i` and
  `--max-chars` work as with `get`.
- `-i` shows the status and response headers. Messages go to stderr.
- `--proxy URL` sends the request through a proxy and overrides `proxy` from the config (see below).
- The exit code is 1 on a policy or network error. HTTP 4xx/5xx counts as success.

## Proxy

```bash
surfshield --proxy socks5h://127.0.0.1:1082 get https://ifconfig.me
```

Or permanently in the config, under `[http]`: `proxy = "socks5h://127.0.0.1:1082"`. Supported are
`socks5://`, `socks5h://` and `http://`, always with an **IP address** and a port (no hostname,
so no DNS is involved around the proxy itself). The proxy may be on loopback or the LAN; it is
explicitly configured and therefore not subject to the IP check.

| Scheme | DNS resolution | What the policy still checks |
|---|---|---|
| `socks5://` | local, via the policy resolver | everything, including the IP check after DNS; the proxy gets the checked IP |
| `socks5h://` | at the proxy | scheme, denylist, ports and IP literals in the URL |
| `http://` | at the proxy | scheme, denylist, ports and IP literals in the URL |

With `socks5h://` and `http://` the proxy decides where a hostname goes; if a name points to an
internal address behind the proxy, the policy cannot stop that. Use `socks5://` if the
full IP check must keep applying, or a proxy that refuses internal addresses itself.

## Security

- **Denylist**: everything is allowed except `denied_domains` (`*.example.com` also blocks example.com itself) and `denied_ports`.
- **No internal network**: loopback, private (RFC1918), link-local (incl. cloud metadata `169.254.169.254`),
  CGNAT, multicast, IPv6 ULA and IPv4-in-IPv6 variants are blocked. The check happens **after DNS resolution**
  and the connection goes to exactly the checked addresses (no DNS rebinding). Can be disabled with
  `allow_private_ips = true` for local development.
- **Redirects** are followed manually (max. `max_redirects`); every hop goes through the policy again.
  On a redirect to another origin, `Authorization`, `Cookie` and `Proxy-Authorization` are removed.
- **Redirects of POST/PUT/PATCH/DELETE** follow browser rules: after a 303 it becomes a GET without body,
  as after a 301/302 on a POST. Otherwise method and body are kept, but **only within the same
  origin**: a state-changing request is never repeated on another origin (the body may contain
  credentials, and the effect was meant for this site). That gives an error with the target URL;
  if you want that, send the request there explicitly yourself.
- **Methods**: `allowed_methods` (default all six). Restrict to `["GET", "HEAD"]` for read-only
  access, or remove just `DELETE`; the other tools then return a policy error.
- **Headers**: the AI may send headers, except `denied_request_headers` (default incl. `Host`,
  `Content-Length`, `Transfer-Encoding`, `Proxy-*`). CR/LF injection is refused; max. 50 headers and 8 KB.
- **Limits**: max. body (10 MB), max. request body (1 MB), max. output (100,000 characters), connect timeout (5s) and total timeout (30s).
- Only `http`/`https`, no credentials in the URL, no cookies, no system proxy
  (only an explicitly configured proxy, see [Proxy](#proxy)).
- `save_to` stays within `download_dir`: no absolute paths or `..`, symlinks pointing outside are refused,
  and a truncated body is never saved.

## Configuration

See [surfshield.example.toml](surfshield.example.toml). Search order: `--config`, `./surfshield.toml`,
`~/.config/surfshield/config.toml`; without a file the defaults apply.

Logging goes to stderr; set the level with `SURFSHIELD_LOG=info`.

## Development

```bash
cargo test
```

The tests only run against a local mock server (wiremock); no external sites are accessed.
