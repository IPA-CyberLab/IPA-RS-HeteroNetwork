use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

fn section<'a>(source: &'a str, start: &str, end: &str) -> Result<&'a str, &'static str> {
    let (_, tail) = source
        .split_once(start)
        .ok_or("schema section start missing")?;
    let (section, _) = tail.split_once(end).ok_or("schema section end missing")?;
    Ok(section)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/http_mesh.rs");
    let root = env::var_os("CARGO_MANIFEST_DIR").ok_or("manifest directory missing")?;
    let root = Path::new(&root);
    let source = fs::read_to_string(root.join("src/lib.rs"))?;
    let mesh = fs::read_to_string(root.join("src/http_mesh.rs"))?;
    let mut digest = Sha256::new();
    for text in [
        section(
            &source,
            "const ADMIN_CAPABILITY_SCHEMA:",
            "\nfn admin_anchor(",
        )?,
        section(
            &source,
            "    async fn migrate_once(",
            "\n}\n\nimpl PostgresControlPlaneStore {",
        )?,
        section(&mesh, "pub(crate) const SCHEMA:", "\n];")?,
    ] {
        digest.update((text.len() as u64).to_be_bytes());
        digest.update(text.as_bytes());
    }
    println!(
        "cargo:rustc-env=HETERONETWORK_POSTGRES_SCHEMA_VERSION={:x}",
        digest.finalize()
    );
    Ok(())
}
