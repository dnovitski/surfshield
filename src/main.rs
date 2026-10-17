use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use reqwest::Method;

use surfshield::config::Config;
use surfshield::fetch::{FetchResponse, Fetcher, RequestBody};
use surfshield::output::{self, Format};

#[derive(Parser)]
#[command(version, about = "Safe, policy-controlled web access for AI agents")]
struct Cli {
    /// Config file (default: ./surfshield.toml, then ~/.config/surfshield/config.toml)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Send requests through this proxy, e.g. socks5h://127.0.0.1:1080 (overrides the config)
    #[arg(long, global = true, value_name = "URL")]
    proxy: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch a URL with HTTP GET
    Get {
        url: String,
        #[command(flatten)]
        args: RequestArgs,
    },
    /// Send an HTTP POST and print the response
    Post {
        url: String,
        #[command(flatten)]
        body: BodyArgs,
        #[command(flatten)]
        args: RequestArgs,
    },
    /// Send an HTTP PUT and print the response
    Put {
        url: String,
        #[command(flatten)]
        body: BodyArgs,
        #[command(flatten)]
        args: RequestArgs,
    },
    /// Send an HTTP PATCH and print the response
    Patch {
        url: String,
        #[command(flatten)]
        body: BodyArgs,
        #[command(flatten)]
        args: RequestArgs,
    },
    /// Send an HTTP DELETE and print the response
    Delete {
        url: String,
        #[command(flatten)]
        body: BodyArgs,
        #[command(flatten)]
        args: RequestArgs,
    },
    /// Send an HTTP HEAD request and print the response headers
    Head {
        url: String,
        /// Extra request header (repeatable)
        #[arg(short = 'H', long = "header", value_name = "NAME: VALUE")]
        headers: Vec<String>,
    },
    /// Run as an MCP server over stdio
    Serve,
}

#[derive(Args)]
struct BodyArgs {
    /// Request body, sent as-is; @FILE reads it from a file, @- from stdin
    /// (default Content-Type: application/x-www-form-urlencoded, like curl)
    #[arg(short, long, value_name = "DATA", group = "body")]
    data: Option<String>,
    /// JSON request body (or @FILE / @-), sent with Content-Type: application/json
    #[arg(long, value_name = "JSON", group = "body")]
    json: Option<String>,
    /// Form field, URL-encoded (repeatable)
    #[arg(long = "field", value_name = "NAME=VALUE", group = "body")]
    fields: Vec<String>,
}

impl BodyArgs {
    /// The request body, or `None` when no body option was given.
    fn into_body(self) -> anyhow::Result<Option<RequestBody>> {
        if let Some(data) = self.data {
            return Ok(Some(RequestBody::new(
                read_data(&data)?,
                Some("application/x-www-form-urlencoded"),
            )));
        }
        if let Some(json) = self.json {
            let bytes = read_data(&json)?;
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .context("--json is not valid JSON")?;
            return Ok(Some(RequestBody::new(bytes, Some("application/json"))));
        }
        if self.fields.is_empty() {
            return Ok(None);
        }
        let fields = self
            .fields
            .iter()
            .map(|f| {
                f.split_once('=')
                    .with_context(|| format!("invalid --field {f:?}, expected NAME=VALUE"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Some(RequestBody::form(fields)))
    }
}

#[derive(Args)]
struct RequestArgs {
    /// Print the exact response body instead of Markdown
    #[arg(long)]
    raw: bool,
    /// Write the exact response body to a file
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Extra request header, e.g. -H "Accept: application/json" (repeatable)
    #[arg(short = 'H', long = "header", value_name = "NAME: VALUE")]
    headers: Vec<String>,
    /// Print the status line and response headers before the body
    #[arg(short, long)]
    include: bool,
    /// Maximum number of characters to print (default: max_output_chars from config)
    #[arg(long)]
    max_chars: Option<usize>,
}

#[tokio::main]
async fn main() -> ExitCode {
    // stdout carries MCP messages and response bodies, so logs go to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SURFSHIELD_LOG")
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let mut config = Config::load(cli.config.as_deref())?;
    if let Some(proxy) = cli.proxy {
        config.http.proxy = Some(proxy);
        config.validate()?;
    }
    match cli.command {
        Command::Serve => surfshield::mcp::serve(&config).await,
        Command::Head { url, headers } => {
            let fetcher = Fetcher::new(&config)?;
            let response = fetcher
                .fetch(Method::HEAD, &url, &parse_headers(&headers)?)
                .await?;
            report_redirects(&response);
            print_head(&response, &mut std::io::stdout().lock())?;
            Ok(())
        }
        Command::Get { url, args } => {
            let fetcher = Fetcher::new(&config)?;
            let response = fetcher
                .fetch(Method::GET, &url, &parse_headers(&args.headers)?)
                .await?;
            print_response(&response, &args, config.limits.max_output_chars)
        }
        Command::Post { url, body, args } => send(&config, Method::POST, &url, body, &args).await,
        Command::Put { url, body, args } => send(&config, Method::PUT, &url, body, &args).await,
        Command::Patch { url, body, args } => send(&config, Method::PATCH, &url, body, &args).await,
        Command::Delete { url, body, args } => {
            send(&config, Method::DELETE, &url, body, &args).await
        }
    }
}

async fn send(
    config: &Config,
    method: Method,
    url: &str,
    body: BodyArgs,
    args: &RequestArgs,
) -> anyhow::Result<()> {
    let body = body.into_body()?;
    let fetcher = Fetcher::new(config)?;
    let response = fetcher
        .fetch_with_body(method, url, &parse_headers(&args.headers)?, body)
        .await?;
    print_response(&response, args, config.limits.max_output_chars)
}

/// Reads a curl-style data argument: `@FILE` from a file, `@-` from stdin,
/// anything else literally.
fn read_data(arg: &str) -> anyhow::Result<Vec<u8>> {
    match arg.strip_prefix('@') {
        Some("-") => {
            let mut data = Vec::new();
            std::io::stdin()
                .read_to_end(&mut data)
                .context("cannot read stdin")?;
            Ok(data)
        }
        Some(path) => std::fs::read(path).with_context(|| format!("cannot read {path}")),
        None => Ok(arg.as_bytes().to_vec()),
    }
}

fn print_response(
    response: &FetchResponse,
    args: &RequestArgs,
    max_output_chars: usize,
) -> anyhow::Result<()> {
    report_redirects(response);
    if response.body_truncated {
        eprintln!(
            "warning: body truncated at max_body_bytes ({} bytes)",
            response.body.len()
        );
    }
    let mut stdout = std::io::stdout().lock();
    if args.include {
        print_head(response, &mut stdout)?;
    }

    if let Some(path) = &args.output {
        let saved = output::save_body(response, path, true)?;
        eprintln!(
            "saved {} bytes to {} (sha256 {})",
            saved.bytes,
            saved.path.display(),
            saved.sha256
        );
    } else if args.raw {
        stdout.write_all(&response.body)?;
    } else {
        let max_chars = args.max_chars.unwrap_or(max_output_chars);
        let rendered = output::render(response, Format::Markdown, max_chars);
        if let Some(note) = &rendered.note {
            eprintln!("{note}");
        }
        if let Some(text) = rendered.text {
            writeln!(stdout, "{text}")?;
        }
        if rendered.truncated {
            eprintln!("output truncated at {max_chars} characters");
        }
    }
    stdout.flush()?;
    Ok(())
}

fn parse_headers(raw: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    raw.iter()
        .map(|h| {
            let Some((name, value)) = h.split_once(':') else {
                bail!("invalid header {h:?}, expected \"Name: value\"");
            };
            Ok((name.trim().to_string(), value.trim().to_string()))
        })
        .collect::<anyhow::Result<_>>()
        .context("invalid -H argument")
}

fn report_redirects(response: &FetchResponse) {
    if !response.redirects.is_empty() {
        eprintln!("redirected to {}", response.final_url);
    }
}

fn print_head(response: &FetchResponse, out: &mut impl Write) -> std::io::Result<()> {
    writeln!(
        out,
        "HTTP {} {}",
        response.status.as_u16(),
        response.status.canonical_reason().unwrap_or("")
    )?;
    for (name, value) in &response.headers {
        writeln!(out, "{name}: {}", String::from_utf8_lossy(value.as_bytes()))?;
    }
    writeln!(out)
}
