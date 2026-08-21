//! JSON envelope protocol — Task (server→agent) and TaskResponse (agent→server).

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct Task {
    pub id:            String,
    #[serde(rename = "type")]
    pub kind:          String,
    pub args:          serde_json::Value,
    pub expires_at:    Option<f64>,
    pub session_token: Option<String>,
}

impl Task {
    /// Convenience: get a string arg by key, returning "" if missing or not a string.
    pub fn arg_str(&self, key: &str) -> &str {
        self.args.get(key).and_then(|v| v.as_str()).unwrap_or("")
    }

    /// Convenience: get a u64 arg by key, returning 0 if missing or not a number.
    pub fn arg_u64(&self, key: &str) -> u64 {
        self.args.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
    }
}

#[derive(Serialize, Default, Clone)]
pub struct StagedFile {
    pub cloud_path:   String,
    pub filename:     String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source_path:  String,
}

#[derive(Serialize, Default)]
pub struct TaskResponse {
    pub id:            String,
    #[serde(rename = "type")]
    pub kind:          String,
    pub status:        String,
    pub output:        String,
    pub cwd:           String,
    pub staging_path:  String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub staging_files: Vec<StagedFile>,
    pub artifacts:     Vec<Artifact>,
    pub session_token: String,
}

impl TaskResponse {
    fn token(task: &Task) -> String {
        task.session_token.clone().unwrap_or_default()
    }

    pub fn ok(task: &Task, output: String) -> Self {
        Self {
            id:            task.id.clone(),
            kind:          task.kind.clone(),
            status:        "ok".to_string(),
            output,
            session_token: Self::token(task),
            ..Default::default()
        }
    }

    pub fn ok_cwd(task: &Task, output: String, cwd: String) -> Self {
        Self {
            id:            task.id.clone(),
            kind:          task.kind.clone(),
            status:        "ok".to_string(),
            output,
            cwd,
            session_token: Self::token(task),
            ..Default::default()
        }
    }

    pub fn ok_staging(task: &Task, output: String, staging_path: String) -> Self {
        Self {
            id:            task.id.clone(),
            kind:          task.kind.clone(),
            status:        "ok".to_string(),
            output,
            staging_path,
            session_token: Self::token(task),
            ..Default::default()
        }
    }

    pub fn ok_staged_files(task: &Task, output: String, files: Vec<StagedFile>) -> Self {
        Self {
            id:            task.id.clone(),
            kind:          task.kind.clone(),
            status:        "ok".to_string(),
            output,
            staging_files: files,
            session_token: Self::token(task),
            ..Default::default()
        }
    }

    pub fn ok_artifacts(task: &Task, output: String, artifacts: Vec<Artifact>) -> Self {
        Self {
            id:            task.id.clone(),
            kind:          task.kind.clone(),
            status:        "ok".to_string(),
            output,
            artifacts,
            session_token: Self::token(task),
            ..Default::default()
        }
    }

    pub fn err(task: &Task, msg: String) -> Self {
        Self {
            id:            task.id.clone(),
            kind:          task.kind.clone(),
            status:        "error".to_string(),
            output:        msg,
            session_token: Self::token(task),
            ..Default::default()
        }
    }
}

#[derive(Serialize)]
pub struct Artifact {
    pub op:   String,
    #[serde(rename = "type")]
    pub kind: String,
    pub path: String,
}

/// Parse ARTIFACT:/ARTIFACT_REMOVED: marker lines from persist function output.
/// Returns (cleaned_output, artifacts_vec).
/// Lines matching `ARTIFACT:<type>:<path>` → op="add"; `ARTIFACT_REMOVED:<type>:<path>` → op="remove".
pub fn parse_artifacts(raw: &str) -> (String, Vec<Artifact>) {
    let mut clean = Vec::new();
    let mut artifacts = Vec::new();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("ARTIFACT_REMOVED:") {
            let mut p = rest.splitn(2, ':');
            let kind = p.next().unwrap_or("").to_string();
            let path = p.next().unwrap_or("").to_string();
            if !kind.is_empty() && !path.is_empty() {
                artifacts.push(Artifact { op: "remove".to_string(), kind, path });
            }
        } else if let Some(rest) = line.strip_prefix("ARTIFACT:") {
            let mut p = rest.splitn(2, ':');
            let kind = p.next().unwrap_or("").to_string();
            let path = p.next().unwrap_or("").to_string();
            if !kind.is_empty() && !path.is_empty() {
                artifacts.push(Artifact { op: "add".to_string(), kind, path });
            }
        } else {
            clean.push(line);
        }
    }
    (clean.join("\n"), artifacts)
}
