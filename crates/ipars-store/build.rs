use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let (_, tail) = source
        .split_once(start)
        .expect("schema section start missing");
    let (section, _) = tail.split_once(end).expect("schema section end missing");
    section
}

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/http_mesh.rs");
    let root = env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory missing");
    let root = Path::new(&root);
    let source = fs::read_to_string(root.join("src/lib.rs")).expect("store source missing");
    let mesh = fs::read_to_string(root.join("src/http_mesh.rs")).expect("mesh source missing");
    let mut digest = Sha256::new();
    for text in [
        section(
            &source,
            "const ADMIN_CAPABILITY_SCHEMA:",
            "\nfn admin_anchor(",
        ),
        section(
            &source,
            "    async fn migrate_once(",
            "\n}\n\nimpl PostgresControlPlaneStore {",
        ),
        section(&mesh, "pub(crate) const SCHEMA:", "\n];"),
    ] {
        digest.update((text.len() as u64).to_be_bytes());
        digest.update(text.as_bytes());
    }
    println!(
        "cargo:rustc-env=HETERONETWORK_POSTGRES_SCHEMA_VERSION={:x}",
        digest.finalize()
    );
}
