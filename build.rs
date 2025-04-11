use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    // If the `DOCS_RS` environment variable is set, we are building for docs.rs
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:rustc-env=SQLX_OFFLINE=1")
    }
}
