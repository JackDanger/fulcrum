//! CLI glue for the fair-compare + audit commands: a GENERIC JSON spec that
//! describes the tools and corpora to compare, plus reference-digest building.
//!
//! The whole point is that NOTHING here names a specific competitor. A user
//! writes a small JSON file:
//!
//! ```json
//! {
//!   "subject": "tool-a",
//!   "reference": { "bin": "gzip", "argv": ["-dc", "{input}"] },
//!   "tools": [
//!     { "name": "tool-a", "bin": "gzip",  "argv": ["-dc", "{input}"],
//!       "thread_arg": null, "auto_arg": null },
//!     { "name": "tool-b", "bin": "zstd",  "argv": ["-dcq", "{input}"],
//!       "thread_arg": "-T{n}", "auto_arg": "-T0" }
//!   ],
//!   "corpora": [
//!     { "name": "text-1m", "kind": "compressible",   "path": "/tmp/a.gz",  "plain_bytes": 1048576 },
//!     { "name": "rand-1m", "kind": "incompressible", "path": "/tmp/b.gz",  "plain_bytes": 1048576 }
//!   ],
//!   "threads": ["T1", "T4", "auto"]
//! }
//! ```
//!
//! The reference output is computed by running `reference` on each corpus (the
//! "first tool or `gzip -dc`" rule from the fair-compare spec), so every tool is
//! held to the SAME correct bytes.

use crate::compare::{Corpus, OutputMode, ThreadCell, ToolSpec};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A tool entry in the JSON spec.
#[derive(Debug, Deserialize)]
pub struct ToolEntry {
    pub name: String,
    pub bin: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub thread_arg: Option<String>,
    #[serde(default)]
    pub auto_arg: Option<String>,
    /// "stdout" (default) or "file" (then argv should contain `{output}`).
    #[serde(default)]
    pub output: Option<String>,
    #[serde(default)]
    pub version_arg: Option<String>,
}

impl ToolEntry {
    fn to_spec(&self) -> ToolSpec {
        let mut s = ToolSpec {
            name: self.name.clone(),
            bin: self.bin.clone(),
            argv: self.argv.clone(),
            thread_arg: self.thread_arg.clone(),
            auto_threads_arg: self.auto_arg.clone(),
            writes_to: match self.output.as_deref() {
                Some("file") => OutputMode::File,
                _ => OutputMode::Stdout,
            },
            version_arg: self
                .version_arg
                .clone()
                .unwrap_or_else(|| "--version".to_string()),
        };
        if s.version_arg.is_empty() {
            s.version_arg = "--version".to_string();
        }
        s
    }
}

/// A reference-decoder entry (computes the correct bytes).
#[derive(Debug, Deserialize)]
pub struct ReferenceEntry {
    pub bin: String,
    pub argv: Vec<String>,
    /// "stdout" (default) or "file".
    #[serde(default)]
    pub output: Option<String>,
}

/// A corpus entry in the JSON spec (reference digest is computed, not stored).
#[derive(Debug, Deserialize)]
pub struct CorpusEntry {
    pub name: String,
    pub kind: String,
    pub path: String,
    #[serde(default)]
    pub plain_bytes: Option<u64>,
}

/// The whole compare spec.
#[derive(Debug, Deserialize)]
pub struct CompareSpec {
    pub subject: String,
    pub reference: ReferenceEntry,
    pub tools: Vec<ToolEntry>,
    pub corpora: Vec<CorpusEntry>,
    #[serde(default)]
    pub threads: Vec<String>,
}

impl CompareSpec {
    pub fn load(path: &Path) -> std::io::Result<CompareSpec> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("compare spec parse {}: {e}", path.display()),
            )
        })
    }

    /// The tool specs.
    pub fn tool_specs(&self) -> Vec<ToolSpec> {
        self.tools.iter().map(|t| t.to_spec()).collect()
    }

    /// The thread cells, parsed from the `threads` list (defaults to T1, auto).
    pub fn thread_cells(&self) -> Vec<ThreadCell> {
        if self.threads.is_empty() {
            return vec![ThreadCell::Fixed(1), ThreadCell::Auto];
        }
        self.threads
            .iter()
            .filter_map(|t| parse_thread_cell(t))
            .collect()
    }

    /// Build the corpora, COMPUTING the reference digest for each by running the
    /// reference decoder. Returns an error string if a reference run fails (a
    /// fair comparison cannot proceed without correct bytes to check against).
    pub fn build_corpora(&self) -> Result<Vec<Corpus>, String> {
        let ref_output = self.reference.output.as_deref().unwrap_or("stdout");
        let mut out = Vec::new();
        for c in &self.corpora {
            let path = PathBuf::from(&c.path);
            if !path.exists() {
                return Err(format!(
                    "corpus '{}' path does not exist: {}",
                    c.name, c.path
                ));
            }
            let (digest, plain_len) =
                run_reference(&self.reference.bin, &self.reference.argv, &path, ref_output)
                    .map_err(|e| format!("reference decode of corpus '{}' failed: {e}", c.name))?;
            let plain_bytes = c.plain_bytes.unwrap_or(plain_len);
            out.push(Corpus {
                name: c.name.clone(),
                kind: c.kind.clone(),
                path,
                plain_bytes,
                reference: digest,
            });
        }
        Ok(out)
    }
}

/// Parse a thread-cell token: "T8" → Fixed(8), "auto" → Auto.
pub fn parse_thread_cell(tok: &str) -> Option<ThreadCell> {
    let t = tok.trim().to_ascii_lowercase();
    if t == "auto" || t == "0" {
        return Some(ThreadCell::Auto);
    }
    if let Some(rest) = t.strip_prefix('t') {
        return rest.parse::<usize>().ok().map(ThreadCell::Fixed);
    }
    t.parse::<usize>().ok().map(ThreadCell::Fixed)
}

/// Run the reference decoder on a corpus, returning (sha256 of output, byte len).
fn run_reference(
    bin: &str,
    argv: &[String],
    input: &Path,
    output_mode: &str,
) -> std::io::Result<([u8; 32], u64)> {
    let resolved = crate::compare::resolve_in_path(bin).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("reference bin '{bin}' not on PATH"),
        )
    })?;
    let out_path = if output_mode == "file" {
        Some(std::env::temp_dir().join("fulcrum_reference.out"))
    } else {
        None
    };
    let args: Vec<String> = argv
        .iter()
        .map(|t| {
            t.replace("{input}", &input.display().to_string()).replace(
                "{output}",
                &out_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
            )
        })
        .collect();
    let mut cmd = Command::new(&resolved);
    cmd.args(&args);
    cmd.stderr(std::process::Stdio::null());
    if output_mode == "stdout" {
        cmd.stdout(std::process::Stdio::piped());
    } else {
        cmd.stdout(std::process::Stdio::null());
    }
    let o = cmd.output()?;
    if !o.status.success() {
        return Err(std::io::Error::other(format!(
            "reference decoder exited nonzero: {:?}",
            o.status
        )));
    }
    let bytes = match (output_mode, &out_path) {
        ("stdout", _) => o.stdout,
        (_, Some(p)) => {
            let b = std::fs::read(p)?;
            let _ = std::fs::remove_file(p);
            b
        }
        _ => Vec::new(),
    };
    Ok((crate::compare::sha256(&bytes), bytes.len() as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_thread_cells_all_forms() {
        assert_eq!(parse_thread_cell("T8"), Some(ThreadCell::Fixed(8)));
        assert_eq!(parse_thread_cell("t1"), Some(ThreadCell::Fixed(1)));
        assert_eq!(parse_thread_cell("auto"), Some(ThreadCell::Auto));
        assert_eq!(parse_thread_cell("0"), Some(ThreadCell::Auto));
        assert_eq!(parse_thread_cell("4"), Some(ThreadCell::Fixed(4)));
    }

    #[test]
    fn spec_parses_and_defaults_threads() {
        let json = r#"{
            "subject": "tool-a",
            "reference": { "bin": "gzip", "argv": ["-dc", "{input}"] },
            "tools": [
                { "name": "tool-a", "bin": "gzip", "argv": ["-dc", "{input}"] }
            ],
            "corpora": [
                { "name": "c1", "kind": "compressible", "path": "/tmp/x.gz", "plain_bytes": 1024 }
            ]
        }"#;
        let spec: CompareSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.subject, "tool-a");
        // No threads → default [T1, auto].
        assert_eq!(
            spec.thread_cells(),
            vec![ThreadCell::Fixed(1), ThreadCell::Auto]
        );
        let specs = spec.tool_specs();
        assert_eq!(specs[0].name, "tool-a");
        assert_eq!(specs[0].writes_to, OutputMode::Stdout);
    }
}
