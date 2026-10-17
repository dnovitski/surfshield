use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SaveError;
use crate::fetch::FetchResponse;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, rmcp::schemars::JsonSchema,
)]
#[schemars(crate = "rmcp::schemars")]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// HTML converted to Markdown, JSON pretty-printed, other text as-is.
    #[default]
    Markdown,
    /// The exact response body, unmodified.
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BodyEncoding {
    Text,
    Base64,
}

#[derive(Debug)]
pub struct RenderedBody {
    /// `None` when the body could not be rendered in the requested format (binary content).
    pub text: Option<String>,
    pub encoding: BodyEncoding,
    pub truncated: bool,
    pub note: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Html,
    Json,
    Text,
    Binary,
}

pub fn render(response: &FetchResponse, format: Format, max_chars: usize) -> RenderedBody {
    match format {
        Format::Markdown => render_markdown(response, max_chars),
        Format::Raw => render_raw(&response.body, max_chars),
    }
}

fn render_markdown(response: &FetchResponse, max_chars: usize) -> RenderedBody {
    let (mime, charset) = parse_content_type(response.content_type());
    let kind = classify(&mime, &response.body);
    let text = match kind {
        Kind::Binary => {
            return RenderedBody {
                text: None,
                encoding: BodyEncoding::Text,
                truncated: false,
                note: Some(format!(
                    "binary content ({}); use format \"raw\" or save_to to get the bytes",
                    if mime.is_empty() {
                        "unknown type"
                    } else {
                        &mime
                    }
                )),
            };
        }
        Kind::Html => {
            let html = decode(&response.body, charset.as_deref());
            html_to_markdown(&html)
        }
        Kind::Json => {
            let text = decode(&response.body, charset.as_deref());
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| serde_json::to_string_pretty(&v).ok())
                .unwrap_or_else(|| text.into_owned())
        }
        Kind::Text => decode(&response.body, charset.as_deref()).into_owned(),
    };
    let (text, truncated) = truncate_chars(text, max_chars);
    RenderedBody {
        text: Some(text),
        encoding: BodyEncoding::Text,
        truncated,
        note: None,
    }
}

/// Returns the body byte-for-byte: as text when it is valid UTF-8, otherwise base64.
fn render_raw(body: &[u8], max_chars: usize) -> RenderedBody {
    match std::str::from_utf8(body) {
        Ok(text) => {
            let (text, truncated) = truncate_chars(text.to_string(), max_chars);
            RenderedBody {
                text: Some(text),
                encoding: BodyEncoding::Text,
                truncated,
                note: truncated.then(|| "output truncated; use save_to for the full body".into()),
            }
        }
        Err(_) => {
            // Every 3 input bytes become 4 base64 characters.
            let max_bytes = (max_chars / 4) * 3;
            let truncated = body.len() > max_bytes;
            let slice = if truncated { &body[..max_bytes] } else { body };
            RenderedBody {
                text: Some(base64::engine::general_purpose::STANDARD.encode(slice)),
                encoding: BodyEncoding::Base64,
                truncated,
                note: Some(if truncated {
                    "body is not valid UTF-8 and was base64-encoded; output truncated, use save_to for the full body".into()
                } else {
                    "body is not valid UTF-8 and was base64-encoded".into()
                }),
            }
        }
    }
}

fn html_to_markdown(html: &str) -> String {
    let converter = htmd::HtmlToMarkdown::builder()
        .skip_tags(vec![
            "script", "style", "noscript", "template", "svg", "canvas", "iframe", "object",
            "embed", "link", "meta",
        ])
        .build();
    converter.convert(html).unwrap_or_else(|_| html.to_string())
}

/// Returns the lowercased media type without parameters, and the charset if present.
fn parse_content_type(content_type: Option<&str>) -> (String, Option<String>) {
    let Some(content_type) = content_type else {
        return (String::new(), None);
    };
    let mut parts = content_type.split(';');
    let mime = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let charset = parts.find_map(|param| {
        let (key, value) = param.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches('"').to_string())
    });
    (mime, charset)
}

fn classify(mime: &str, body: &[u8]) -> Kind {
    match mime {
        "text/html" | "application/xhtml+xml" => Kind::Html,
        "application/json" => Kind::Json,
        m if m.ends_with("+json") => Kind::Json,
        m if m.starts_with("text/") => Kind::Text,
        "application/xml"
        | "application/javascript"
        | "application/ecmascript"
        | "application/x-javascript"
        | "application/x-www-form-urlencoded"
        | "application/x-ndjson"
        | "application/yaml"
        | "application/toml" => Kind::Text,
        m if m.ends_with("+xml") => Kind::Text,
        "" => sniff(body),
        _ => Kind::Binary,
    }
}

/// Guesses the kind of a body that came without a Content-Type.
fn sniff(body: &[u8]) -> Kind {
    let Ok(text) = std::str::from_utf8(body) else {
        return Kind::Binary;
    };
    let start = text
        .trim_start()
        .get(..15)
        .unwrap_or("")
        .to_ascii_lowercase();
    if start.starts_with("<!doctype html") || start.starts_with("<html") {
        Kind::Html
    } else {
        Kind::Text
    }
}

fn decode<'a>(body: &'a [u8], charset: Option<&str>) -> Cow<'a, str> {
    let encoding = charset
        .and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()))
        .unwrap_or(encoding_rs::UTF_8);
    // `decode` honours a BOM over the declared charset, like browsers do.
    encoding.decode(body).0
}

fn truncate_chars(mut text: String, max_chars: usize) -> (String, bool) {
    match text.char_indices().nth(max_chars) {
        Some((byte_index, _)) => {
            text.truncate(byte_index);
            (text, true)
        }
        None => (text, false),
    }
}

/// Response headers as a map; repeated headers become a list.
pub fn headers_to_json(
    headers: &reqwest::header::HeaderMap,
) -> BTreeMap<String, serde_json::Value> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        map.entry(name.to_string())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    map.into_iter()
        .map(|(name, mut values)| {
            let value = if values.len() == 1 {
                serde_json::Value::String(values.remove(0))
            } else {
                serde_json::Value::from(values)
            };
            (name, value)
        })
        .collect()
}

#[derive(Debug, Serialize)]
pub struct SavedFile {
    pub path: PathBuf,
    pub bytes: usize,
    pub sha256: String,
}

/// Resolves a caller-supplied relative path inside `download_dir`, rejecting anything
/// that could end up outside of it (absolute paths, `..`, symlinked directories).
pub fn resolve_in_download_dir(download_dir: &Path, relative: &str) -> Result<PathBuf, SaveError> {
    let relative = Path::new(relative);
    let mut has_file_name = false;
    for component in relative.components() {
        match component {
            Component::Normal(_) => has_file_name = true,
            Component::CurDir => {}
            _ => return Err(SaveError::PathOutsideDownloadDir),
        }
    }
    if !has_file_name {
        return Err(SaveError::PathOutsideDownloadDir);
    }

    std::fs::create_dir_all(download_dir)?;
    let root = download_dir.canonicalize()?;
    let target = root.join(relative);
    let parent = target.parent().ok_or(SaveError::PathOutsideDownloadDir)?;
    std::fs::create_dir_all(parent)?;
    if !parent.canonicalize()?.starts_with(&root) {
        return Err(SaveError::PathOutsideDownloadDir);
    }
    Ok(target)
}

/// Writes the exact response body to `path`.
pub fn save_body(
    response: &FetchResponse,
    path: &Path,
    overwrite: bool,
) -> Result<SavedFile, SaveError> {
    if response.body_truncated {
        return Err(SaveError::BodyTruncated(response.body.len()));
    }
    write_file(path, &response.body, overwrite)?;
    Ok(SavedFile {
        path: path.to_path_buf(),
        bytes: response.body.len(),
        sha256: hex::encode(Sha256::digest(&response.body)),
    })
}

fn write_file(path: &Path, data: &[u8], overwrite: bool) -> Result<(), SaveError> {
    if !overwrite {
        // `create_new` also refuses to follow a symlink at `path`.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    SaveError::AlreadyExists(path.display().to_string())
                }
                _ => SaveError::Io(e),
            })?;
        file.write_all(data)?;
        return Ok(());
    }
    // Write to a temporary file and rename it over the target: the rename replaces a
    // symlink at `path` instead of writing through it.
    let file_name = path
        .file_name()
        .ok_or(SaveError::PathOutsideDownloadDir)?
        .to_string_lossy();
    let tmp = path.with_file_name(format!(
        ".{file_name}.surfshield-{}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(result?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_parsing() {
        assert_eq!(
            parse_content_type(Some("Text/HTML; charset=\"ISO-8859-1\"")),
            ("text/html".into(), Some("ISO-8859-1".into()))
        );
        assert_eq!(parse_content_type(None), (String::new(), None));
    }

    #[test]
    fn classification() {
        assert_eq!(classify("text/html", b""), Kind::Html);
        assert_eq!(classify("application/ld+json", b""), Kind::Json);
        assert_eq!(classify("image/svg+xml", b""), Kind::Text);
        assert_eq!(classify("image/png", b""), Kind::Binary);
        assert_eq!(classify("", b"<!DOCTYPE html><p>x"), Kind::Html);
        assert_eq!(classify("", &[0xff, 0xfe, 0x00]), Kind::Binary);
    }

    #[test]
    fn decodes_declared_charset() {
        assert_eq!(
            decode(&[0x63, 0x61, 0x66, 0xe9], Some("iso-8859-1")),
            "café"
        );
    }

    #[test]
    fn truncates_on_char_boundary() {
        assert_eq!(truncate_chars("héllo".into(), 2), ("hé".into(), true));
        assert_eq!(truncate_chars("héllo".into(), 5), ("héllo".into(), false));
    }

    #[test]
    fn markdown_strips_scripts() {
        let md = html_to_markdown("<h1>Title</h1><script>alert(1)</script><p>Body</p>");
        assert!(md.contains("# Title"));
        assert!(md.contains("Body"));
        assert!(!md.contains("alert"));
    }

    #[test]
    fn raw_keeps_exact_text_and_base64_for_binary() {
        let html = "<!doctype html>\r\n<p>  exact  </p>\n";
        let rendered = render_raw(html.as_bytes(), 1000);
        assert_eq!(rendered.text.as_deref(), Some(html));
        assert_eq!(rendered.encoding, BodyEncoding::Text);

        let binary = [0u8, 0xff, 0x10, 0x80];
        let rendered = render_raw(&binary, 1000);
        assert_eq!(rendered.encoding, BodyEncoding::Base64);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(rendered.text.unwrap())
            .unwrap();
        assert_eq!(decoded, binary);
    }

    #[test]
    fn download_paths_are_confined() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["../x", "/etc/passwd", "a/../../x", "", "."] {
            assert!(
                matches!(
                    resolve_in_download_dir(dir.path(), bad),
                    Err(SaveError::PathOutsideDownloadDir)
                ),
                "{bad:?} should be rejected"
            );
        }
        let ok = resolve_in_download_dir(dir.path(), "sub/page.html").unwrap();
        assert!(ok.starts_with(dir.path().canonicalize().unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_directory_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
        assert!(matches!(
            resolve_in_download_dir(dir.path(), "escape/x.html"),
            Err(SaveError::PathOutsideDownloadDir)
        ));
    }

    #[test]
    fn write_file_respects_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        write_file(&path, b"one", false).unwrap();
        assert!(matches!(
            write_file(&path, b"two", false),
            Err(SaveError::AlreadyExists(_))
        ));
        write_file(&path, b"two", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
    }
}
