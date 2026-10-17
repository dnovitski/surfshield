//! End-to-end test of the `serve` subcommand: speaks MCP JSON-RPC over the binary's stdio.

use std::process::Stdio;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use wiremock::matchers::{body_json, body_string, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct McpClient {
    _child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
    next_id: u64,
}

impl McpClient {
    async fn start(config_path: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_surfshield"))
            .args(["serve", "--config"])
            .arg(config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut client = Self {
            _child: child,
            stdin,
            stdout,
            next_id: 1,
        };
        let init = client
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"}
                }),
            )
            .await;
        assert_eq!(init["result"]["serverInfo"]["name"], "surfshield");
        client
            .send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        client
    }

    async fn send(&mut self, message: Value) {
        let mut line = serde_json::to_string(&message).unwrap();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        loop {
            let line = self
                .stdout
                .next_line()
                .await
                .unwrap()
                .expect("server closed stdout");
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["id"] == id {
                return message;
            }
        }
    }

    async fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let response = self
            .request("tools/call", json!({"name": tool, "arguments": arguments}))
            .await;
        response["result"].clone()
    }
}

fn text(result: &Value, index: usize) -> &str {
    result["content"][index]["text"].as_str().unwrap()
}

#[tokio::test]
async fn mcp_tools_end_to_end() {
    let server = MockServer::start().await;
    let html = "<!doctype html>\n<h1>Hallo</h1>\n<script>evil()</script>\n";
    Mock::given(path("/page"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(html, "text/html; charset=utf-8"))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let downloads = dir.path().join("downloads");
    let config_path = dir.path().join("surfshield.toml");
    std::fs::write(
        &config_path,
        format!(
            "[policy]\nallow_private_ips = true\n[download]\ndownload_dir = {:?}\n",
            downloads.display().to_string()
        ),
    )
    .unwrap();

    let mut client = McpClient::start(&config_path).await;
    let page = format!("{}/page", server.uri());

    let tools = client.request("tools/list", json!({})).await;
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for name in [
        "fetch_url",
        "head_url",
        "post_url",
        "put_url",
        "patch_url",
        "delete_url",
    ] {
        assert!(names.contains(&name), "{name} missing");
    }

    // Markdown (default)
    let result = client.call("fetch_url", json!({"url": page})).await;
    assert_ne!(result["isError"], true);
    let meta: Value = serde_json::from_str(text(&result, 0)).unwrap();
    assert_eq!(meta["status"], 200);
    assert_eq!(meta["format"], "markdown");
    let body = text(&result, 1);
    assert!(body.contains("# Hallo"));
    assert!(body.contains("UNTRUSTED EXTERNAL CONTENT"));
    assert!(!body.contains("evil()"));

    // Raw: exact HTML, no wrapper
    let result = client
        .call("fetch_url", json!({"url": page, "format": "raw"}))
        .await;
    assert_eq!(text(&result, 1), html);

    // save_to writes the exact bytes inside the download directory
    let result = client
        .call(
            "fetch_url",
            json!({"url": page, "save_to": "site/page.html"}),
        )
        .await;
    let meta: Value = serde_json::from_str(text(&result, 0)).unwrap();
    assert_eq!(meta["saved_to"]["bytes"], html.len());
    assert_eq!(
        std::fs::read_to_string(downloads.join("site/page.html")).unwrap(),
        html
    );

    // Saving again without overwrite fails, with overwrite succeeds
    let result = client
        .call(
            "fetch_url",
            json!({"url": page, "save_to": "site/page.html"}),
        )
        .await;
    assert_eq!(result["isError"], true);
    let result = client
        .call(
            "fetch_url",
            json!({"url": page, "save_to": "site/page.html", "overwrite": true}),
        )
        .await;
    assert_ne!(result["isError"], true);

    // Escaping the download directory is refused
    let result = client
        .call(
            "fetch_url",
            json!({"url": page, "save_to": "../escape.html"}),
        )
        .await;
    assert_eq!(result["isError"], true);
    assert!(!dir.path().join("escape.html").exists());

    // Policy errors are reported as tool errors
    let result = client
        .call("fetch_url", json!({"url": "file:///etc/passwd"}))
        .await;
    assert_eq!(result["isError"], true);
    assert!(text(&result, 0).contains("not allowed"));

    // POST with a JSON body
    Mock::given(method("POST"))
        .and(path("/api"))
        .and(body_json(json!({"name": "surfshield"})))
        .respond_with(ResponseTemplate::new(201).set_body_raw("{\"id\":7}", "application/json"))
        .mount(&server)
        .await;
    let api = format!("{}/api", server.uri());
    let result = client
        .call(
            "post_url",
            json!({"url": api, "json": {"name": "surfshield"}}),
        )
        .await;
    assert_ne!(result["isError"], true);
    let meta: Value = serde_json::from_str(text(&result, 0)).unwrap();
    assert_eq!(meta["status"], 201);
    assert!(text(&result, 1).contains("\"id\": 7"));

    // Only one kind of body at a time
    let result = client
        .call(
            "post_url",
            json!({"url": api, "body": "x", "form": {"a": "b"}}),
        )
        .await;
    assert_eq!(result["isError"], true);

    // PUT, PATCH and DELETE
    Mock::given(method("PUT"))
        .and(path("/api/7"))
        .and(body_json(json!({"name": "nieuw"})))
        .respond_with(ResponseTemplate::new(200).set_body_string("replaced"))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/api/7"))
        .and(body_string("name=x"))
        .respond_with(ResponseTemplate::new(200).set_body_string("patched"))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/7"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let item = format!("{}/api/7", server.uri());
    let result = client
        .call("put_url", json!({"url": item, "json": {"name": "nieuw"}}))
        .await;
    assert!(text(&result, 1).contains("replaced"));
    let result = client
        .call("patch_url", json!({"url": item, "form": {"name": "x"}}))
        .await;
    assert!(text(&result, 1).contains("patched"));
    let result = client.call("delete_url", json!({"url": item})).await;
    let meta: Value = serde_json::from_str(text(&result, 0)).unwrap();
    assert_eq!(meta["status"], 204);

    // HEAD
    let result = client.call("head_url", json!({"url": page})).await;
    let meta: Value = serde_json::from_str(text(&result, 0)).unwrap();
    assert_eq!(meta["status"], 200);
    assert_eq!(meta["content_type"], "text/html; charset=utf-8");
}
