use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn depx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_depx"))
}

fn project(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn analyze_threshold_is_a_real_process_gate() {
    let output = depx()
        .args([
            "analyze",
            project("examples/demo-app").to_str().unwrap(),
            "--fail-on",
            "warning",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(serde_json::from_slice::<serde_json::Value>(&output.stdout).is_ok());
}

#[test]
fn sarif_output_contains_no_terminal_status_text() {
    let output = depx()
        .args([
            "analyze",
            project("tests/fixtures/npm-workspace").to_str().unwrap(),
            "--sarif",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["version"], "2.1.0");
    assert!(value["runs"][0]["results"].is_array());
}

#[test]
fn baseline_suppresses_existing_findings_but_preserves_the_gate() {
    let root = temporary_project();
    copy_demo_project(&root);

    let baseline = depx()
        .args(["baseline", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(baseline.status.success());
    assert!(root.join("depx-baseline.json").is_file());
    let baseline_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join("depx-baseline.json")).unwrap())
            .unwrap();
    assert_eq!(baseline_json["schemaVersion"], 2);

    let analyzed = depx()
        .args([
            "analyze",
            root.to_str().unwrap(),
            "--fail-on",
            "warning",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(analyzed.status.success());
    let value: serde_json::Value = serde_json::from_slice(&analyzed.stdout).unwrap();
    assert!(value["findings"].as_array().unwrap().is_empty());

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn analysis_json_exposes_versioned_project_units() {
    let output = depx()
        .args([
            "analyze",
            project("tests/fixtures/npm-workspace").to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schemaVersion"], 3);
    assert_ne!(value["schemaVersion"], 2);
    assert_eq!(value["units"].as_array().unwrap().len(), 2);
    assert!(value["units"]
        .as_array()
        .unwrap()
        .iter()
        .all(|unit| unit["name"].is_string()));
    assert!(value["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| { evidence["owner"] == "unit:packages/app" }));
}

#[test]
fn duplicate_json_is_versioned_and_informational() {
    let output = depx()
        .args([
            "duplicates",
            project("tests/fixtures/cargo-normalized").to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schemaVersion"], 2);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("transitive_count"));
}

fn temporary_project() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("depx-cli-{}-{nonce}", std::process::id()));
    fs::create_dir_all(path.join("src")).unwrap();
    path
}

fn copy_demo_project(destination: &Path) {
    let source = project("examples/demo-app");
    for relative in ["package.json", "package-lock.json", "src/index.ts"] {
        let target = destination.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::copy(source.join(relative), target).unwrap();
    }
}
