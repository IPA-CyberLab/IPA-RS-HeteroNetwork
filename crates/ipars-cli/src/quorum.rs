use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Args, Subcommand};
use ed25519_dalek::Signer;
use ipars_control_plane_http::quorum::{
    Round1Request, Round2Request, Round2Response, QUORUM_PROOF_HEADER, QUORUM_TOKEN_HEADER,
};
use ipars_quorum::{
    dkg, frost, CapabilityClaims, CapabilityToken, Manifest, Member, RequestProof, SCHEMA_VERSION,
};
use ipnet::IpNet;
use rand_core::{OsRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CeremonyRoster {
    schema_version: u32,
    ceremony_id: String,
    cluster_id: String,
    epoch: u64,
    members: Vec<Member>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Round1Packet {
    roster_hash: [u8; 32],
    member_id: u16,
    package: dkg::round1::Package,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Round1State {
    roster_hash: [u8; 32],
    member_id: u16,
    secret: dkg::round1::SecretPackage,
    own_packet: Round1Packet,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Round2State {
    roster_hash: [u8; 32],
    transcript_hash: [u8; 32],
    member_id: u16,
    secret: dkg::round2::SecretPackage,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Round2Packet {
    roster_hash: [u8; 32],
    transcript_hash: [u8; 32],
    sender: u16,
    recipient: u16,
    package: dkg::round2::Package,
}

fn roster(path: &Path) -> anyhow::Result<(CeremonyRoster, [u8; 32])> {
    let mut value: CeremonyRoster = read_json(path, false)?;
    let valid_id = |value: &str| {
        !value.is_empty()
            && value.len() <= 256
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    };
    if value.schema_version != SCHEMA_VERSION
        || !valid_id(&value.ceremony_id)
        || !valid_id(&value.cluster_id)
        || !(2..=1024).contains(&value.members.len())
    {
        bail!("invalid fixed DKG ceremony roster");
    }
    value.members.sort_by_key(|member| member.identifier);
    let mut identifiers = BTreeSet::new();
    let mut nodes = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    for member in &value.members {
        let url = Url::parse(&member.endpoint)
            .map_err(|_| anyhow::anyhow!("invalid DKG roster endpoint"))?;
        if member.identifier == 0
            || !identifiers.insert(member.identifier)
            || !valid_id(&member.node_id)
            || !nodes.insert(&member.node_id)
            || !endpoints.insert(url.to_string())
            || !matches!(url.scheme(), "http" | "https")
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("DKG roster requires unique fixed members, identifiers and endpoints");
        }
    }
    let hash = digest_json("heteronetwork-cli-dkg-roster-v1", &value)?;
    Ok((value, hash))
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> anyhow::Result<[u8; 32]> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| anyhow::anyhow!("cannot encode DKG transcript"))?;
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(bytes);
    Ok(hash.finalize().into())
}

fn load_round1(
    roster: &CeremonyRoster,
    hash: [u8; 32],
    paths: &[PathBuf],
) -> anyhow::Result<BTreeMap<u16, Round1Packet>> {
    let mut packets = BTreeMap::new();
    for path in paths {
        let packet: Round1Packet = read_json(path, false)?;
        if packet.roster_hash != hash
            || !roster
                .members
                .iter()
                .any(|member| member.identifier == packet.member_id)
            || packets.insert(packet.member_id, packet).is_some()
        {
            bail!("round-one packet has a foreign ceremony, unknown member or duplicate sender");
        }
    }
    if packets.len() != roster.members.len() {
        bail!("round one requires exactly one packet from every frozen member, including self");
    }
    Ok(packets)
}

fn other_round1(
    packets: &BTreeMap<u16, Round1Packet>,
    member_id: u16,
) -> anyhow::Result<BTreeMap<frost::Identifier, dkg::round1::Package>> {
    packets
        .iter()
        .filter(|(id, _)| **id != member_id)
        .map(|(id, packet)| {
            Ok((
                frost::Identifier::try_from(*id)
                    .map_err(|_| anyhow::anyhow!("invalid DKG participant identifier"))?,
                packet.package.clone(),
            ))
        })
        .collect()
}

fn dkg_part1(args: DkgPart1Args) -> anyhow::Result<()> {
    let (roster, hash) = roster(&args.roster)?;
    if !roster
        .members
        .iter()
        .any(|member| member.identifier == args.member_id)
    {
        bail!("local member is not in the frozen ceremony roster");
    }
    let secret_file = reserve_output(&args.secret_out)?;
    let packet_file = reserve_output(&args.packet_out)?;
    let id = frost::Identifier::try_from(args.member_id)
        .map_err(|_| anyhow::anyhow!("invalid DKG identifier"))?;
    let count = u16::try_from(roster.members.len())?;
    let (secret, package) = dkg::part1(id, count, count / 2 + 1, OsRng)
        .map_err(|_| anyhow::anyhow!("FROST DKG part one failed"))?;
    let packet = Round1Packet {
        roster_hash: hash,
        member_id: args.member_id,
        package,
    };
    write_json(packet_file, &packet)?;
    write_json(
        secret_file,
        &Round1State {
            roster_hash: hash,
            member_id: args.member_id,
            secret,
            own_packet: packet,
        },
    )
}

fn dkg_part2(args: DkgPart2Args) -> anyhow::Result<()> {
    let (roster, hash) = roster(&args.roster)?;
    let state: Round1State = read_json(&args.secret, true)?;
    let packets = load_round1(&roster, hash, &args.round1_packet)?;
    let own_id = frost::Identifier::try_from(state.member_id)
        .map_err(|_| anyhow::anyhow!("invalid local DKG identifier"))?;
    if state.roster_hash != hash
        || state.own_packet.roster_hash != hash
        || state.own_packet.member_id != state.member_id
        || packets.get(&state.member_id).map(|packet| &packet.package)
            != Some(&state.own_packet.package)
        || state.secret.identifier() != &own_id
        || usize::from(*state.secret.max_signers()) != roster.members.len()
        || usize::from(*state.secret.min_signers()) != roster.members.len() / 2 + 1
        || state.secret.commitment() != state.own_packet.package.commitment()
    {
        bail!("local DKG state does not match the frozen round-one transcript");
    }
    let transcript_hash = digest_json("heteronetwork-cli-dkg-round1-v1", &packets)?;
    let others = other_round1(&packets, state.member_id)?;
    let output = reserve_output(&args.secret_out)?;
    let mut directory = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory
        .create(&args.packets_out)
        .context("round-two packet directory must be a new path")?;
    let (secret, outgoing) = dkg::part2(state.secret, &others)
        .map_err(|_| anyhow::anyhow!("FROST DKG part two rejected the transcript"))?;
    for member in &roster.members {
        if member.identifier == state.member_id {
            continue;
        }
        let id = frost::Identifier::try_from(member.identifier)
            .map_err(|_| anyhow::anyhow!("invalid DKG identifier"))?;
        let package = outgoing
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("missing recipient DKG package"))?;
        write_json(
            reserve_output(
                &args
                    .packets_out
                    .join(format!("to-{}.json", member.identifier)),
            )?,
            &Round2Packet {
                roster_hash: hash,
                transcript_hash,
                sender: state.member_id,
                recipient: member.identifier,
                package: package.clone(),
            },
        )?;
    }
    write_json(
        output,
        &Round2State {
            roster_hash: hash,
            transcript_hash,
            member_id: state.member_id,
            secret,
        },
    )
}

fn dkg_part3(args: DkgPart3Args) -> anyhow::Result<()> {
    let (roster, hash) = roster(&args.roster)?;
    let state: Round2State = read_json(&args.secret, true)?;
    let packets = load_round1(&roster, hash, &args.round1_packet)?;
    let own_id = frost::Identifier::try_from(state.member_id)
        .map_err(|_| anyhow::anyhow!("invalid local DKG identifier"))?;
    if state.roster_hash != hash
        || state.transcript_hash != digest_json("heteronetwork-cli-dkg-round1-v1", &packets)?
        || !roster
            .members
            .iter()
            .any(|member| member.identifier == state.member_id)
        || state.secret.identifier() != &own_id
        || usize::from(*state.secret.max_signers()) != roster.members.len()
        || usize::from(*state.secret.min_signers()) != roster.members.len() / 2 + 1
        || packets
            .get(&state.member_id)
            .map(|packet| packet.package.commitment())
            != Some(state.secret.commitment())
    {
        bail!("round-three ceremony or round-one transcript mismatch");
    }
    let mut incoming = BTreeMap::new();
    for path in &args.round2_packet {
        let packet: Round2Packet = read_json(path, true)?;
        if packet.roster_hash != hash
            || packet.transcript_hash != state.transcript_hash
            || packet.recipient != state.member_id
            || packet.sender == state.member_id
            || !roster
                .members
                .iter()
                .any(|member| member.identifier == packet.sender)
        {
            bail!("round-two packet has a foreign transcript, sender or recipient");
        }
        let id = frost::Identifier::try_from(packet.sender)
            .map_err(|_| anyhow::anyhow!("invalid DKG sender"))?;
        if incoming.insert(id, packet.package).is_some() {
            bail!("duplicate round-two sender");
        }
    }
    if incoming.len() + 1 != roster.members.len() {
        bail!("missing frozen-member round-two packets");
    }
    let key_file = reserve_output(&args.key_share_out)?;
    let manifest_file = reserve_output(&args.manifest_out)?;
    let (key, public) = dkg::part3(
        &state.secret,
        &other_round1(&packets, state.member_id)?,
        &incoming,
    )
    .map_err(|_| anyhow::anyhow!("FROST DKG part three rejected the ceremony"))?;
    let manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        cluster_id: roster.cluster_id,
        epoch: roster.epoch,
        members: roster.members,
        public_key_package: public
            .serialize()
            .map_err(|_| anyhow::anyhow!("cannot encode public FROST keys"))?,
    };
    manifest.validate()?;
    write_json(key_file, &key)?;
    write_json(manifest_file, &manifest)
}

#[derive(Debug, Subcommand)]
pub enum QuorumCommand {
    /// Generate an Ed25519 requester identity, not a quorum dealer key.
    RequesterKeygen(RequesterKeygenArgs),
    /// Offline distributed key-generation ceremony; no trusted dealer.
    Dkg {
        #[command(subcommand)]
        command: DkgCommand,
    },
    /// Bind an administrative request to its exact HTTP method, path and body.
    Request(RequestArgs),
    /// Collect approvals from frozen manifest members and write a quorum token.
    Issue(IssueArgs),
    /// Execute an approved request with requester proof of possession.
    Execute(ExecuteArgs),
}

#[derive(Debug, Args)]
pub struct RequesterKeygenArgs {
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    public_out: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum DkgCommand {
    Part1(DkgPart1Args),
    Part2(DkgPart2Args),
    Part3(DkgPart3Args),
}

#[derive(Debug, Args)]
pub struct DkgPart1Args {
    #[arg(long)]
    roster: PathBuf,
    #[arg(long)]
    member_id: u16,
    #[arg(long)]
    secret_out: PathBuf,
    #[arg(long)]
    packet_out: PathBuf,
}

#[derive(Debug, Args)]
pub struct DkgPart2Args {
    #[arg(long)]
    roster: PathBuf,
    #[arg(long)]
    secret: PathBuf,
    #[arg(long, required = true)]
    round1_packet: Vec<PathBuf>,
    #[arg(long)]
    secret_out: PathBuf,
    /// New private directory for recipient-specific round-two packets.
    #[arg(long)]
    packets_out: PathBuf,
}

#[derive(Debug, Args)]
pub struct DkgPart3Args {
    #[arg(long)]
    roster: PathBuf,
    #[arg(long)]
    secret: PathBuf,
    #[arg(long, required = true)]
    round1_packet: Vec<PathBuf>,
    #[arg(long, required = true)]
    round2_packet: Vec<PathBuf>,
    #[arg(long)]
    key_share_out: PathBuf,
    #[arg(long)]
    manifest_out: PathBuf,
}

#[derive(Debug, Args)]
pub struct RequestArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    requester_key: PathBuf,
    #[arg(long)]
    method: String,
    /// Exact allowlisted administrative path; query strings are not permitted.
    #[arg(long)]
    path: String,
    /// Raw bytes: no JSON normalization or trailing newline changes.
    #[arg(long)]
    body: PathBuf,
    #[arg(long, default_value_t = 180, value_parser = clap::value_parser!(u64).range(1..=300))]
    ttl_seconds: u64,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Clone, Default, Args)]
pub struct TransportArgs {
    /// Explicit VPN networks permitting manifest-frozen literal-IP HTTP endpoints.
    #[arg(long)]
    vpn_cidr: Vec<IpNet>,
    #[cfg(test)]
    #[arg(skip)]
    allow_test_loopback: bool,
}

#[derive(Debug, Args)]
pub struct IssueArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    requester_key: PathBuf,
    #[arg(long)]
    oidc_token: PathBuf,
    #[arg(long)]
    body: PathBuf,
    #[arg(long)]
    token_out: PathBuf,
    #[command(flatten)]
    transport: TransportArgs,
}

#[derive(Debug, Args)]
pub struct ExecuteArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    token: PathBuf,
    #[arg(long)]
    requester_key: PathBuf,
    #[arg(long)]
    body: PathBuf,
    #[arg(long)]
    control_plane_url: String,
    /// Optional private file containing the raw response; never printed.
    #[arg(long)]
    response_out: Option<PathBuf>,
    #[command(flatten)]
    transport: TransportArgs,
}

fn read_file(path: &Path, private: bool) -> anyhow::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .context("cannot open quorum input file")?;
    let metadata = file
        .metadata()
        .context("cannot inspect quorum input file")?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        bail!("quorum input must be a bounded regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = nix::unistd::geteuid().as_raw();
        if (metadata.uid() != 0 && metadata.uid() != uid) || metadata.mode() & 0o022 != 0 {
            bail!("quorum input has an untrusted owner or is writable by other users");
        }
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o777 != 0o600 || metadata.uid() != nix::unistd::geteuid().as_raw() {
            bail!("private quorum input must be owned by this user with mode 0600");
        }
    }
    #[cfg(not(unix))]
    if private {
        bail!("private quorum files require Unix permission enforcement");
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("cannot read quorum input file")?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        bail!("quorum input exceeds size limit");
    }
    Ok(bytes)
}

fn read_json<T: DeserializeOwned>(path: &Path, private: bool) -> anyhow::Result<T> {
    let bytes = Zeroizing::new(read_file(path, private)?);
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid quorum JSON input"))
}

fn requester_key(path: &Path) -> anyhow::Result<ed25519_dalek::SigningKey> {
    let bytes = Zeroizing::new(read_file(path, true)?);
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid requester private-key encoding"))?;
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(text.trim_end_matches(['\r', '\n']))
            .map_err(|_| {
                anyhow::anyhow!("requester key must be base64url encoded Ed25519 signing bytes")
            })?,
    );
    let mut key = Zeroizing::new([0_u8; 32]);
    if decoded.len() != key.len() {
        bail!("requester key must contain exactly 32 decoded bytes");
    }
    key.copy_from_slice(&decoded);
    Ok(ed25519_dalek::SigningKey::from_bytes(&key))
}

fn oidc_token(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let bytes = Zeroizing::new(read_file(path, true)?);
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid OIDC token encoding"))?
        .trim_end_matches(['\r', '\n']);
    if text.is_empty() || text.len() > 32768 || !text.bytes().all(|byte| byte.is_ascii_graphic()) {
        bail!("OIDC token file must contain one bounded non-whitespace token");
    }
    Ok(Zeroizing::new(text.to_owned()))
}

fn reserve_output(path: &Path) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    bail!("private quorum files require Unix permission enforcement");
    options
        .open(path)
        .context("cannot create new quorum output; existing paths are never overwritten")
}

fn write_json<T: Serialize>(mut file: File, value: &T) -> anyhow::Result<()> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(value).map_err(|_| anyhow::anyhow!("cannot serialize quorum output"))?,
    );
    file.write_all(&bytes)
        .context("cannot write private quorum output")?;
    file.sync_all().context("cannot sync private quorum output")
}

fn endpoint(value: &str, transport: &TransportArgs) -> anyhow::Result<Url> {
    let url = Url::parse(value).map_err(|_| anyhow::anyhow!("invalid quorum endpoint URL"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        bail!("quorum endpoint must not contain credentials, query or fragment");
    }
    match url.scheme() {
        "https" if url.host().is_some() => {}
        "http" => {
            let ip: IpAddr = match url.host() {
                Some(url::Host::Ipv4(ip)) => ip.into(),
                Some(url::Host::Ipv6(ip)) => ip.into(),
                _ => bail!("HTTP quorum endpoints require literal VPN IP addresses"),
            };
            #[cfg(test)]
            if transport.allow_test_loopback && ip.is_loopback() {
                return Ok(url);
            }
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ipars_types::ip_addr_is_globally_routable(ip)
                || !transport
                    .vpn_cidr
                    .iter()
                    .any(|network| network.contains(&ip))
            {
                bail!("HTTP quorum endpoint is not in an explicitly approved VPN network");
            }
        }
        _ => bail!("quorum endpoints require HTTPS or explicitly approved VPN-IP HTTP"),
    }
    Ok(url)
}

fn http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| anyhow::anyhow!("cannot initialize quorum HTTPS client"))
}

fn exact_target(base: &Url, target: &str) -> anyhow::Result<Url> {
    if base.path() != "/"
        || !target.starts_with('/')
        || target.starts_with("//")
        || target.contains('#')
        || target.contains('\\')
        || !target.is_ascii()
    {
        bail!("execution requires an origin URL and an exact origin-form request target");
    }
    let url = base
        .join(target)
        .map_err(|_| anyhow::anyhow!("invalid execution request target"))?;
    let actual = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    if url.origin() != base.origin() || actual != target {
        bail!("execution target would be normalized or change the approved origin");
    }
    Ok(url)
}

async fn response_bytes(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_FILE_BYTES)
    {
        bail!("quorum HTTP response exceeds size limit");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("quorum HTTP response transport failure"))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_FILE_BYTES as usize {
            bail!("quorum HTTP response exceeds size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn now() -> anyhow::Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

fn load_manifest(path: &Path) -> anyhow::Result<Manifest> {
    let manifest: Manifest = read_json(path, false)?;
    manifest.validate()?;
    Ok(manifest)
}

fn proof(
    claims: &CapabilityClaims,
    key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<RequestProof> {
    if claims.requester_public_key != key.verifying_key().to_bytes() {
        bail!("requester private key does not match approved claims");
    }
    Ok(RequestProof {
        signature: key.sign(&claims.proof_bytes()).to_bytes().to_vec(),
    })
}

fn validate_request(
    manifest: &Manifest,
    request: &Round1Request,
    body: &[u8],
    key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<()> {
    request.claims.validate(manifest, now()?)?;
    request.proof.verify(&request.claims)?;
    if request.claims.body_sha256 != <[u8; 32]>::from(Sha256::digest(body))
        || request.claims.requester_public_key != key.verifying_key().to_bytes()
    {
        bail!("request body or requester identity differs from the approved request");
    }
    Ok(())
}

fn create_request(args: RequestArgs) -> anyhow::Result<()> {
    let manifest = load_manifest(&args.manifest)?;
    let key = requester_key(&args.requester_key)?;
    let body = Zeroizing::new(read_file(&args.body, false)?);
    let timestamp = now()?;
    let mut request_id = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut request_id)
        .map_err(|_| anyhow::anyhow!("secure request randomness unavailable"))?;
    let claims = CapabilityClaims {
        schema_version: SCHEMA_VERSION,
        cluster_id: manifest.cluster_id.clone(),
        epoch: manifest.epoch,
        manifest_digest: manifest.digest()?,
        method: args.method,
        path: args.path,
        body_sha256: Sha256::digest(&body).into(),
        requester_public_key: key.verifying_key().to_bytes(),
        request_id,
        issued_at: timestamp,
        expires_at: timestamp
            .checked_add(args.ttl_seconds)
            .context("invalid request lifetime")?,
    };
    claims.validate(&manifest, timestamp)?;
    let request = Round1Request {
        proof: proof(&claims, &key)?,
        claims,
    };
    write_json(reserve_output(&args.out)?, &request)
}

fn generate_requester_key(args: RequesterKeygenArgs) -> anyhow::Result<()> {
    let mut secret = reserve_output(&args.out)?;
    let mut public = reserve_output(&args.public_out)?;
    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(Zeroizing::new(key.to_bytes()).as_ref()));
    secret.write_all(encoded.as_bytes())?;
    secret.sync_all()?;
    public.write_all(
        URL_SAFE_NO_PAD
            .encode(key.verifying_key().to_bytes())
            .as_bytes(),
    )?;
    public.sync_all()?;
    Ok(())
}

async fn post_round<T: Serialize, R: DeserializeOwned>(
    client: &reqwest::Client,
    url: Url,
    token: &str,
    body: &T,
) -> anyhow::Result<R> {
    let response = client
        .post(url)
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("quorum signer transport failed; no automatic retry"))?;
    if response.status() != reqwest::StatusCode::OK {
        bail!("quorum signer returned HTTP {}", response.status().as_u16());
    }
    let bytes = Zeroizing::new(response_bytes(response).await?);
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid quorum signer response"))
}

async fn issue(args: IssueArgs) -> anyhow::Result<()> {
    let manifest = load_manifest(&args.manifest)?;
    let request: Round1Request = read_json(&args.request, true)?;
    let key = requester_key(&args.requester_key)?;
    let body = Zeroizing::new(read_file(&args.body, false)?);
    validate_request(&manifest, &request, &body, &key)?;
    let oidc = oidc_token(&args.oidc_token)?;
    let mut members = manifest.members.clone();
    members.sort_by_key(|member| member.identifier);
    // Validate the entire frozen roster before sending any owner credential.
    let endpoints: Vec<_> = members
        .iter()
        .map(|member| {
            let base = endpoint(&member.endpoint, &args.transport)?;
            Ok((
                member.identifier,
                exact_target(&base, "/v1/quorum/round1")?,
                exact_target(&base, "/v1/quorum/round2")?,
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let output = reserve_output(&args.token_out)?;
    let client = http_client()?;
    let threshold = usize::from(manifest.threshold());
    let mut tasks = tokio::task::JoinSet::new();
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(32));
    for (identifier, first, second) in endpoints {
        let client = client.clone();
        let oidc = oidc.clone();
        let request = Round1Request {
            claims: request.claims.clone(),
            proof: request.proof.clone(),
        };
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits
                .acquire_owned()
                .await
                .map_err(|_| anyhow::anyhow!("signer request cancelled"))?;
            let result: ipars_quorum::Round1Response =
                post_round(&client, first, &oidc, &request).await?;
            if result.identifier != identifier || result.session_id == [0; 32] {
                bail!("round-one response identity does not match its frozen endpoint");
            }
            Ok::<_, anyhow::Error>((second, result))
        });
    }
    let mut selected = Vec::new();
    let round_deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    while selected.len() < threshold {
        match tokio::time::timeout_at(round_deadline, tasks.join_next()).await {
            Ok(Some(Ok(Ok(response)))) => selected.push(response),
            Ok(Some(_)) => continue,
            _ => break,
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    if selected.len() < threshold {
        bail!("frozen majority unavailable: received {} of {} required approvals; pending signer sessions expire automatically", selected.len(), threshold);
    }
    validate_request(&manifest, &request, &body, &key)?;
    let mut commitments = BTreeMap::new();
    for (_, response) in &selected {
        let id = frost::Identifier::try_from(response.identifier)
            .map_err(|_| anyhow::anyhow!("invalid signer identifier"))?;
        if commitments.insert(id, response.commitments).is_some() {
            bail!("duplicate signer commitment");
        }
    }
    let package = frost::SigningPackage::new(commitments, &request.claims.signing_bytes());
    let mut shares = tokio::task::JoinSet::new();
    for (url, response) in selected {
        let client = client.clone();
        let oidc = oidc.clone();
        let request = Round2Request {
            session_id: response.session_id,
            claims: request.claims.clone(),
            proof: request.proof.clone(),
            signing_package: package.clone(),
        };
        shares.spawn(async move {
            let result: Round2Response = post_round(&client, url, &oidc, &request).await?;
            Ok::<_, anyhow::Error>((response.identifier, result.signature_share))
        });
    }
    let mut signature_shares = BTreeMap::new();
    let mut failed = false;
    while let Some(result) = shares.join_next().await {
        match result {
            Ok(Ok((identifier, share))) => {
                let id = frost::Identifier::try_from(identifier)
                    .map_err(|_| anyhow::anyhow!("invalid signer identifier"))?;
                if signature_shares.insert(id, share).is_some() {
                    failed = true;
                }
            }
            _ => failed = true,
        }
    }
    if failed || signature_shares.len() != threshold {
        bail!("round two failed; do not reuse commitments or retry execution with uncertain authorization");
    }
    let signature = frost::aggregate(&package, &signature_shares, &manifest.public_keys()?)
        .map_err(|_| anyhow::anyhow!("threshold signature aggregation failed"))?;
    let token = CapabilityToken {
        claims: request.claims,
        signature: signature
            .serialize()
            .map_err(|_| anyhow::anyhow!("cannot encode threshold signature"))?,
    };
    ipars_quorum::verify_capability(
        &manifest,
        &token,
        &request.proof,
        &token.claims.method,
        &token.claims.path,
        &body,
        now()?,
    )?;
    write_json(output, &token)
}

fn execution_request(
    client: &reqwest::Client,
    target: Url,
    token: &CapabilityToken,
    proof: &RequestProof,
    body: &[u8],
) -> anyhow::Result<reqwest::Request> {
    let method = reqwest::Method::from_bytes(token.claims.method.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid approved HTTP method"))?;
    fn encoded_header<T: Serialize>(value: &T) -> anyhow::Result<reqwest::header::HeaderValue> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(value)
                .map_err(|_| anyhow::anyhow!("cannot encode quorum authorization"))?,
        );
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(&*bytes));
        if encoded.len() > 65536 {
            bail!("quorum authorization header exceeds server limit");
        }
        let mut header = reqwest::header::HeaderValue::from_str(&encoded)
            .map_err(|_| anyhow::anyhow!("invalid quorum authorization header"))?;
        header.set_sensitive(true);
        Ok(header)
    }
    client
        .request(method, target)
        .header(QUORUM_TOKEN_HEADER, encoded_header(token)?)
        .header(QUORUM_PROOF_HEADER, encoded_header(proof)?)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_vec())
        .build()
        .map_err(|_| anyhow::anyhow!("cannot build exact quorum execution request"))
}

async fn execute(args: ExecuteArgs) -> anyhow::Result<()> {
    let manifest = load_manifest(&args.manifest)?;
    let token: CapabilityToken = read_json(&args.token, true)?;
    let key = requester_key(&args.requester_key)?;
    let body = Zeroizing::new(read_file(&args.body, false)?);
    let proof = proof(&token.claims, &key)?;
    ipars_quorum::verify_capability(
        &manifest,
        &token,
        &proof,
        &token.claims.method,
        &token.claims.path,
        &body,
        now()?,
    )?;
    // This explicit operator-selected origin is never learned from a token or signer response.
    let target = exact_target(
        &endpoint(&args.control_plane_url, &args.transport)?,
        &token.claims.path,
    )?;
    let output = args
        .response_out
        .as_deref()
        .map(reserve_output)
        .transpose()?;
    let client = http_client()?;
    let request = execution_request(&client, target, &token, &proof, &body)?;
    let response = client.execute(request).await
        .map_err(|_| anyhow::anyhow!("execution outcome unknown after transport failure; inspect state before a new authorization"))?;
    let status = response.status();
    let bytes = Zeroizing::new(response_bytes(response).await?);
    if let Some(mut file) = output {
        file.write_all(&bytes)
            .context("cannot write private execution response")?;
        file.sync_all()?;
    }
    // Admin enrollment responses can contain credentials; arbitrary response text is never stdout-safe.
    let format = if serde_json::from_slice::<serde_json::Value>(&bytes).is_ok() {
        "json"
    } else {
        "non-json"
    };
    println!(
        "{}",
        serde_json::json!({ "status": status.as_u16(), "body": { "format": format, "bytes": bytes.len(), "content": "redacted" } })
    );
    if !status.is_success() {
        bail!(
            "administrative execution returned HTTP {}; no automatic retry",
            status.as_u16()
        );
    }
    Ok(())
}

pub async fn run(command: QuorumCommand) -> anyhow::Result<()> {
    match command {
        QuorumCommand::RequesterKeygen(args) => generate_requester_key(args)?,
        QuorumCommand::Dkg { command } => match command {
            DkgCommand::Part1(args) => dkg_part1(args)?,
            DkgCommand::Part2(args) => dkg_part2(args)?,
            DkgCommand::Part3(args) => dkg_part3(args)?,
        },
        QuorumCommand::Request(args) => create_request(args)?,
        QuorumCommand::Issue(args) => issue(args).await?,
        QuorumCommand::Execute(args) => return execute(args).await,
    }
    println!(
        "{}",
        serde_json::json!({ "status": "written", "secrets": "private_files_only" })
    );
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> anyhow::Result<Self> {
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "ipars-quorum-cli-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
            Ok(Self(path))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn outputs_are_private_create_new_and_reject_symlinks() -> anyhow::Result<()> {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("private.json");
        write_json(reserve_output(&path)?, &serde_json::json!({ "test": true }))?;
        assert_eq!(std::fs::metadata(&path)?.mode() & 0o777, 0o600);
        let before = read_file(&path, true)?;
        assert!(reserve_output(&path).is_err());
        assert_eq!(read_file(&path, true)?, before);
        let link = scratch.0.join("link");
        symlink(&path, &link)?;
        assert!(reserve_output(&link).is_err());
        assert!(read_file(&link, true).is_err());
        Ok(())
    }

    #[test]
    fn input_permissions_sizes_and_exact_body_are_enforced() -> anyhow::Result<()> {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("body");
        let mut file = reserve_output(&path)?;
        let bytes = b" { \"operation\": true }\n";
        file.write_all(bytes)?;
        assert_eq!(read_file(&path, true)?, bytes);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert!(read_file(&path, true).is_err());
        assert_eq!(read_file(&path, false)?, bytes);
        file.set_len(MAX_FILE_BYTES + 1)?;
        assert!(read_file(&path, false).is_err());
        assert!(read_file(&scratch.0, false).is_err());
        Ok(())
    }

    #[test]
    fn transport_requires_tls_or_explicit_literal_vpn_network() -> anyhow::Result<()> {
        let tls_only = TransportArgs {
            vpn_cidr: Vec::new(),
            ..Default::default()
        };
        assert!(endpoint("https://signer.example.test", &tls_only).is_ok());
        for value in [
            "http://10.20.0.1",
            "http://signer.example.test",
            "https://user:secret@signer.example.test",
            "https://signer.example.test/#fragment",
            "https://signer.example.test/?token=secret",
            "file:///secret",
        ] {
            assert!(endpoint(value, &tls_only).is_err());
        }
        let vpn = TransportArgs {
            vpn_cidr: vec!["10.20.0.0/24".parse()?, "fd00:20::/64".parse()?],
            ..Default::default()
        };
        assert!(endpoint("http://10.20.0.1:8443", &vpn).is_ok());
        assert!(endpoint("http://[fd00:20::1]:8443", &vpn).is_ok());
        for value in [
            "http://10.21.0.1",
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
        ] {
            assert!(endpoint(value, &vpn).is_err());
        }
        let broad = TransportArgs {
            vpn_cidr: vec!["0.0.0.0/0".parse()?, "::/0".parse()?],
            ..Default::default()
        };
        assert!(endpoint("http://8.8.8.8", &broad).is_err());
        assert!(endpoint("http://[2001:4860:4860::8888]", &broad).is_err());
        assert!(endpoint("https://8.8.8.8", &broad).is_ok());
        Ok(())
    }

    #[test]
    fn execution_preserves_exact_target_or_rejects_normalization() -> anyhow::Result<()> {
        let base = Url::parse("https://cp.example.test")?;
        for target in [
            "/v1/admin/policy",
            "/v1/admin/policy?x=1&x=2",
            "/v1/admin/%2f",
        ] {
            assert!(exact_target(&base, target).is_ok());
        }
        for target in [
            "//other.example.test/action",
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1/action#fragment",
            "/v1/white space",
            "/v1\\other",
            "https://other.example.test/",
        ] {
            assert!(exact_target(&base, target).is_err());
        }
        Ok(())
    }

    #[test]
    fn file_ceremony_binds_transcript_and_produces_native_majority_keys() -> anyhow::Result<()> {
        let scratch = Scratch::new()?;
        let roster_path = scratch.0.join("roster.json");
        let ceremony = CeremonyRoster {
            schema_version: SCHEMA_VERSION,
            ceremony_id: "offline-test".into(),
            cluster_id: "test-cluster".into(),
            epoch: 1,
            members: (1..=3)
                .map(|identifier| Member {
                    node_id: format!("node-{identifier}"),
                    identifier,
                    endpoint: format!("https://signer-{identifier}.example.test"),
                })
                .collect(),
        };
        write_json(reserve_output(&roster_path)?, &ceremony)?;
        let round1_paths: Vec<_> = (1..=3)
            .map(|id| scratch.0.join(format!("r1-{id}.json")))
            .collect();
        for id in 1..=3 {
            dkg_part1(DkgPart1Args {
                roster: roster_path.clone(),
                member_id: id,
                secret_out: scratch.0.join(format!("s1-{id}.json")),
                packet_out: round1_paths[usize::from(id - 1)].clone(),
            })?;
        }
        let (roster, hash) = roster(&roster_path)?;
        assert!(load_round1(&roster, hash, &round1_paths[..2]).is_err());
        assert!(load_round1(&roster, [7; 32], &round1_paths).is_err());
        let duplicate = vec![
            round1_paths[0].clone(),
            round1_paths[0].clone(),
            round1_paths[2].clone(),
        ];
        assert!(load_round1(&roster, hash, &duplicate).is_err());
        for id in 1..=3 {
            dkg_part2(DkgPart2Args {
                roster: roster_path.clone(),
                secret: scratch.0.join(format!("s1-{id}.json")),
                round1_packet: round1_paths.clone(),
                secret_out: scratch.0.join(format!("s2-{id}.json")),
                packets_out: scratch.0.join(format!("out-{id}")),
            })?;
        }
        let incoming = |recipient: u16| -> Vec<PathBuf> {
            (1..=3)
                .filter(|id| *id != recipient)
                .map(|id| scratch.0.join(format!("out-{id}/to-{recipient}.json")))
                .collect()
        };
        let mut changed: Round2Packet = read_json(&incoming(1)[0], true)?;
        changed.transcript_hash = [8; 32];
        let bad_packet = scratch.0.join("changed-packet.json");
        write_json(reserve_output(&bad_packet)?, &changed)?;
        let mut bad_incoming = incoming(1);
        bad_incoming[0] = bad_packet;
        assert!(dkg_part3(DkgPart3Args {
            roster: roster_path.clone(),
            secret: scratch.0.join("s2-1.json"),
            round1_packet: round1_paths.clone(),
            round2_packet: bad_incoming,
            key_share_out: scratch.0.join("bad-key.json"),
            manifest_out: scratch.0.join("bad-manifest.json")
        })
        .is_err());
        assert!(!scratch.0.join("bad-key.json").exists());
        let mut engines = Vec::new();
        let mut manifests = Vec::new();
        for id in 1..=3 {
            let key_path = scratch.0.join(format!("key-{id}.json"));
            let manifest_path = scratch.0.join(format!("manifest-{id}.json"));
            dkg_part3(DkgPart3Args {
                roster: roster_path.clone(),
                secret: scratch.0.join(format!("s2-{id}.json")),
                round1_packet: round1_paths.clone(),
                round2_packet: incoming(id),
                key_share_out: key_path.clone(),
                manifest_out: manifest_path.clone(),
            })?;
            let manifest = load_manifest(&manifest_path)?;
            assert_eq!(manifest.threshold(), 2);
            let key: frost::keys::KeyPackage = read_json(&key_path, true)?;
            engines.push(ipars_quorum::SignerEngine::new(
                manifest.clone(),
                &format!("node-{id}"),
                key,
                4,
                60,
            )?);
            manifests.push(manifest);
        }
        assert_eq!(manifests[0].digest()?, manifests[1].digest()?);
        assert_eq!(manifests[1].digest()?, manifests[2].digest()?);
        let key_path = scratch.0.join("requester.key");
        generate_requester_key(RequesterKeygenArgs {
            out: key_path.clone(),
            public_out: scratch.0.join("requester.pub"),
        })?;
        let body_path = scratch.0.join("body.json");
        let body = b" { \"policy\": true }\n";
        reserve_output(&body_path)?.write_all(body)?;
        let request_path = scratch.0.join("request.json");
        create_request(RequestArgs {
            manifest: scratch.0.join("manifest-1.json"),
            requester_key: key_path.clone(),
            method: "PUT".into(),
            path: "/v1/admin/policy".into(),
            body: body_path,
            ttl_seconds: 180,
            out: request_path.clone(),
        })?;
        let request: Round1Request = read_json(&request_path, true)?;
        let requester = requester_key(&key_path)?;
        validate_request(&manifests[0], &request, body, &requester)?;
        assert!(validate_request(&manifests[0], &request, b"{}", &requester).is_err());
        let other_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        assert!(validate_request(&manifests[0], &request, body, &other_key).is_err());
        let timestamp = now()?;
        let first = engines[0].round1(&request.claims, &request.proof, timestamp)?;
        let second = engines[1].round1(&request.claims, &request.proof, timestamp)?;
        let id1 = frost::Identifier::try_from(first.identifier)?;
        let id2 = frost::Identifier::try_from(second.identifier)?;
        let package = frost::SigningPackage::new(
            BTreeMap::from([(id1, first.commitments), (id2, second.commitments)]),
            &request.claims.signing_bytes(),
        );
        let share1 = engines[0].round2(first.session_id, &request.claims, &package, timestamp)?;
        let share2 = engines[1].round2(second.session_id, &request.claims, &package, timestamp)?;
        let signature = frost::aggregate(
            &package,
            &BTreeMap::from([(id1, share1), (id2, share2)]),
            &manifests[0].public_keys()?,
        )?;
        let token = CapabilityToken {
            claims: request.claims,
            signature: signature.serialize()?,
        };
        let wire = execution_request(
            &http_client()?,
            Url::parse("https://cp.example.test/v1/admin/policy")?,
            &token,
            &request.proof,
            body,
        )?;
        assert_eq!(wire.method(), reqwest::Method::PUT);
        assert_eq!(
            wire.body().and_then(reqwest::Body::as_bytes),
            Some(body.as_slice())
        );
        assert_eq!(wire.url().path(), "/v1/admin/policy");
        for name in [QUORUM_TOKEN_HEADER, QUORUM_PROOF_HEADER] {
            assert!(wire
                .headers()
                .get(name)
                .is_some_and(reqwest::header::HeaderValue::is_sensitive));
        }
        let header = wire
            .headers()
            .get(QUORUM_TOKEN_HEADER)
            .context("missing token header")?;
        let decoded: CapabilityToken =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header.as_bytes())?)?;
        assert_eq!(decoded, token);
        ipars_quorum::verify_capability(
            &manifests[0],
            &token,
            &request.proof,
            "PUT",
            "/v1/admin/policy",
            body,
            timestamp,
        )?;
        assert!(ipars_quorum::verify_capability(
            &manifests[0],
            &token,
            &request.proof,
            "PUT",
            "/v1/admin/policy",
            b"{}",
            timestamp
        )
        .is_err());
        assert!(engines[0]
            .round2(first.session_id, &token.claims, &package, timestamp)
            .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn loopback_issue_execute_majority_and_replay() -> anyhow::Result<()> {
        use axum::http::{header, HeaderMap, StatusCode};
        use axum::response::IntoResponse;
        use axum::{routing::get, Json, Router};
        use ipars_control_plane::{
            ControlPlane, ControlPlaneConfig, ControlPlaneJoinService, InMemoryStore,
            InMemoryTokenLedger, IssuerKeyRing,
        };
        use ipars_control_plane_http::{ControlPlaneHttpState, WebAuthProvider, WebUiAuthConfig};
        use std::sync::Arc;
        use tokio::net::TcpListener;

        // JoinSet aborts every server on panic or cancellation as well as normal cleanup.
        let mut servers = tokio::task::JoinSet::new();
        let result = tokio::time::timeout(Duration::from_secs(45), async {
            let scratch = Scratch::new()?;
            let auth_calls = Arc::new(AtomicU64::new(0));
            let calls = auth_calls.clone();
            let provider_listener = TcpListener::bind("127.0.0.1:0").await?;
            let provider_address = provider_listener.local_addr()?;
            let provider = Router::new().route("/realms/test/protocol/openid-connect/userinfo", get(move |headers: HeaderMap| {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()) == Some("Bearer test-owner-token") {
                        Json(serde_json::json!({ "sub": "pinned-owner-subject", "email": "owner@example.test" })).into_response()
                    } else {
                        StatusCode::UNAUTHORIZED.into_response()
                    }
                }
            }));
            servers.spawn(async move { axum::serve(provider_listener, provider).await });
            let auth = WebUiAuthConfig::new(WebAuthProvider::Keycloak,
                "https://issuer.example.test/realms/test".into(), "test-client".into(), None,
                Some(format!("http://{provider_address}/realms/test")), "openid".into())
                .map_err(anyhow::Error::msg)?
                .with_required_email("owner@example.test".into()).map_err(anyhow::Error::msg)?
                .with_required_subject("pinned-owner-subject".into()).map_err(anyhow::Error::msg)?;
            let mut listeners = Vec::new();
            let mut members = Vec::new();
            for identifier in 1..=3 {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                members.push(Member { identifier, node_id: format!("test-node-{identifier}"),
                    endpoint: format!("http://{}", listener.local_addr()?) });
                listeners.push(listener);
            }
            // Dealer generation is confined to this transport fixture. The separate file
            // ceremony test exercises production DKG part1/part2/part3 without a dealer.
            let (shares, public) = frost::keys::generate_with_dealer(3, 2,
                frost::keys::IdentifierList::Default, OsRng)?;
            let manifest = Manifest { schema_version: SCHEMA_VERSION, cluster_id: "loopback-quorum-test".into(),
                epoch: 1, members, public_key_package: public.serialize()? };
            manifest.validate()?;
            for (member, listener) in manifest.members.iter().zip(listeners) {
                let id = frost::Identifier::try_from(member.identifier)?;
                let key = frost::keys::KeyPackage::try_from(shares.get(&id).context("missing fixture key")?.clone())?;
                let router = ipars_control_plane_http::quorum::signer_router(manifest.clone(), key, &member.node_id, auth.clone())
                    .map_err(anyhow::Error::msg)?;
                let server = servers.spawn(async move { axum::serve(listener, router).await });
                if member.identifier == 3 {
                    server.abort();
                    let stopped = tokio::time::timeout(Duration::from_secs(2), servers.join_next()).await?
                        .context("missing stopped signer task")?;
                    assert!(matches!(stopped, Err(error) if error.is_cancelled()));
                }
            }

            let store = Arc::new(InMemoryStore::default());
            let plane = Arc::new(ControlPlane::new(ControlPlaneConfig::new(
                ipars_types::ClusterId::from_string(&manifest.cluster_id), "100.64.0.0/24".parse()?), store));
            plane.bind_admin_quorum_manifest(manifest.epoch, &manifest.digest()?).await?;
            let join = Arc::new(ControlPlaneJoinService::new(plane.clone(), Arc::new(InMemoryTokenLedger::default()), IssuerKeyRing::default()));
            let state = ControlPlaneHttpState::new(plane.clone(), join)
                .require_operator_api_bearer_token("unused-legacy-token".into())
                .with_admin_quorum_manifest(manifest.clone()).map_err(anyhow::Error::msg)?;
            let cp_listener = TcpListener::bind("127.0.0.1:0").await?;
            let cp_url = format!("http://{}", cp_listener.local_addr()?);
            let cp_router = ipars_control_plane_http::router(state);
            servers.spawn(async move { axum::serve(cp_listener, cp_router).await });

            let manifest_path = scratch.0.join("manifest.json");
            write_json(reserve_output(&manifest_path)?, &manifest)?;
            let requester_path = scratch.0.join("requester.key");
            generate_requester_key(RequesterKeygenArgs { out: requester_path.clone(), public_out: scratch.0.join("requester.pub") })?;
            let oidc_path = scratch.0.join("oidc.token");
            reserve_output(&oidc_path)?.write_all(b"test-owner-token")?;
            let policy = ipars_types::ClusterPolicy { allow_ipv6_direct: false, ..Default::default() };
            let body = format!(" {}\n", serde_json::to_string(&serde_json::json!({ "cluster_policy": policy }))?).into_bytes();
            let body_path = scratch.0.join("body.json");
            reserve_output(&body_path)?.write_all(&body)?;
            let request_path = scratch.0.join("request.json");
            create_request(RequestArgs { manifest: manifest_path.clone(), requester_key: requester_path.clone(),
                method: "PUT".into(), path: "/v1/admin/policy".into(), body: body_path.clone(), ttl_seconds: 180, out: request_path.clone() })?;
            let transport = TransportArgs { allow_test_loopback: true, ..Default::default() };
            let token_path = scratch.0.join("token.json");
            issue(IssueArgs { manifest: manifest_path.clone(), request: request_path, requester_key: requester_path.clone(),
                oidc_token: oidc_path, body: body_path.clone(), token_out: token_path.clone(), transport: transport.clone() }).await?;
            assert_eq!(manifest.threshold(), 2);
            assert_eq!(manifest.members.len(), 3);
            assert_eq!(auth_calls.load(Ordering::SeqCst), 4, "both live signers must validate the owner in both rounds");
            let token_json: serde_json::Value = read_json(&token_path, true)?;
            let object = token_json.as_object().context("token must be an object")?;
            assert_eq!(object.keys().map(String::as_str).collect::<BTreeSet<_>>(), BTreeSet::from(["claims", "signature"]));
            let encoded_token = read_file(&token_path, true)?;
            let private_seed = read_file(&requester_path, true)?;
            assert!(!encoded_token.windows(private_seed.len()).any(|window| window == private_seed));
            let token: CapabilityToken = serde_json::from_value(token_json)?;
            assert_eq!(token.claims.body_sha256, <[u8; 32]>::from(Sha256::digest(&body)));
            assert_eq!(std::fs::metadata(&token_path)?.mode() & 0o777, 0o600);
            assert!(plane.current_cluster_policy().await?.allow_ipv6_direct);

            let response_path = scratch.0.join("response.json");
            execute(ExecuteArgs { manifest: manifest_path.clone(), token: token_path.clone(), requester_key: requester_path.clone(),
                body: body_path.clone(), control_plane_url: cp_url.clone(), response_out: Some(response_path.clone()), transport: transport.clone() }).await?;
            let response: serde_json::Value = read_json(&response_path, true)?;
            assert_eq!(response["cluster_policy"]["allow_ipv6_direct"], false);
            assert!(!plane.current_cluster_policy().await?.allow_ipv6_direct);
            let replay_path = scratch.0.join("replay.json");
            let replay = execute(ExecuteArgs { manifest: manifest_path, token: token_path, requester_key: requester_path,
                body: body_path, control_plane_url: cp_url, response_out: Some(replay_path.clone()), transport }).await;
            let error = replay.err().context("replayed capability was accepted")?;
            assert!(error.to_string().contains("HTTP 401"));
            let replay_body: serde_json::Value = read_json(&replay_path, true)?;
            assert!(replay_body.get("error").is_some());
            assert!(!plane.current_cluster_policy().await?.allow_ipv6_direct);
            Ok::<_, anyhow::Error>(())
        }).await;
        servers.abort_all();
        tokio::time::timeout(Duration::from_secs(5), async {
            while servers.join_next().await.is_some() {}
        })
        .await
        .context("loopback server cleanup timed out")?;
        result.context("loopback transport test exceeded deadline")??;
        Ok(())
    }

    #[tokio::test]
    async fn http_client_does_not_follow_redirects() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut input = [0_u8; 4096];
            let mut received = 0;
            while !input[..received].windows(4).any(|part| part == b"\r\n\r\n") {
                if received == input.len() {
                    return Err(std::io::Error::other("test request headers exceed limit"));
                }
                let count = socket.read(&mut input[received..]).await?;
                if count == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
                received += count;
            }
            socket.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/not-allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            Ok::<_, std::io::Error>(())
        });
        let response = http_client()?
            .get(format!("http://{address}/test"))
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        server.await??;
        Ok(())
    }
}
