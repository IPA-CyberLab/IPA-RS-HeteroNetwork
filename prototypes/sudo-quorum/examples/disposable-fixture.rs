//! OFFLINE TEST FIXTURE ONLY. Never install this example or its dealer keys on a host.
use ipars_host_authorization_prototype::privilege::{
    PrivilegeGrant, PrivilegePolicy, SignedPrivilegeGrant,
};
use ipars_quorum::{frost, Manifest, Member};
use rand_core::OsRng;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new("/.dockerenv").exists() || !nix::unistd::geteuid().is_root() {
        return Err("disposable root container only".into());
    }
    let mode = std::env::args().nth(1).ok_or("fixture mode required")?;
    let keys_path = "/opt/quorum-lifecycle/test-keys.json";
    if mode == "provision" {
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, OsRng)?;
        let keys = shares
            .into_values()
            .map(frost::keys::KeyPackage::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let manifest = Manifest {
            schema_version: 1,
            cluster_id: "disposable-sudo".into(),
            epoch: 1,
            members: (1..=3)
                .map(|identifier| Member {
                    identifier,
                    node_id: format!("fixture-{identifier}"),
                    endpoint: format!("https://fixture-{identifier}.invalid/"),
                })
                .collect(),
            public_key_package: public.serialize()?,
        };
        let policy = PrivilegePolicy {
            host_node_id: "fixture-1".into(),
            manifest,
            owners: BTreeMap::from([(1000, "fixture-owner-subject".into())]),
        };
        for (path, bytes) in [
            (keys_path, serde_json::to_vec(&keys)?),
            (
                "/etc/ipars-sudo-prototype.json",
                serde_json::to_vec(&policy)?,
            ),
        ] {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
    } else if mode == "sign" {
        let keys: Vec<frost::keys::KeyPackage> =
            serde_json::from_slice(&std::fs::read(keys_path)?)?;
        let policy: PrivilegePolicy =
            serde_json::from_slice(&std::fs::read("/etc/ipars-sudo-prototype.json")?)?;
        let mut bytes = Vec::new();
        std::io::stdin().take(16385).read_to_end(&mut bytes)?;
        if bytes.len() > 16384 {
            return Err("fixture input too large".into());
        }
        let grant: PrivilegeGrant = serde_json::from_slice(&bytes)?;
        if grant.scope != "sudo"
            || grant.host_node_id != policy.host_node_id
            || grant.runas_uid != 0
            || policy.owners.get(&grant.caller_uid) != Some(&grant.owner_subject)
            || grant.epoch != policy.manifest.epoch
            || grant.manifest_digest != policy.manifest.digest()?
        {
            return Err("fixture grant scope rejected".into());
        }
        let a = keys.first().ok_or("fixture key missing")?;
        let b = keys.get(1).ok_or("fixture key missing")?;
        let (na, ca) = frost::round1::commit(a.signing_share(), &mut OsRng);
        let (nb, cb) = frost::round1::commit(b.signing_share(), &mut OsRng);
        let package = frost::SigningPackage::new(
            BTreeMap::from([(*a.identifier(), ca), (*b.identifier(), cb)]),
            &grant.signing_bytes(),
        );
        let signature = frost::aggregate(
            &package,
            &BTreeMap::from([
                (*a.identifier(), frost::round2::sign(&package, &na, a)?),
                (*b.identifier(), frost::round2::sign(&package, &nb, b)?),
            ]),
            &policy.manifest.public_keys()?,
        )?
        .serialize()?;
        println!(
            "{}",
            serde_json::to_string(&SignedPrivilegeGrant { grant, signature })?
        );
    } else {
        return Err("unknown fixture mode".into());
    }
    Ok(())
}
