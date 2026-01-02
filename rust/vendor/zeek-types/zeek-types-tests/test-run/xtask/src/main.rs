use std::{env, process::Command};

fn main() {
    let task = env::args().nth(1);
    match task.as_deref() {
        Some("build") => build(),
        Some(task) => unimplemented!("unknown task {task}"),
        None => unimplemented!("expected task as first argument"),
    }
}

fn build() {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let status = Command::new(cargo)
        .args(["build", "--workspace"])
        .status()
        .unwrap();
    assert!(status.success());
}
