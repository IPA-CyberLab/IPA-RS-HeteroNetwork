use std::cell::RefCell;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use ipars_types::{NodeId, Route};
use ipnet::IpNet;
use netlink_sys::{AsyncSocket, Socket, SocketAddr};
use nix::sched::CloneFlags;
use rtnetlink::packet_route::{
    route::RouteMessage,
    rule::{RuleAction, RuleAttribute, RuleMessage},
    AddressFamily,
};
use rtnetlink::{Handle, RouteMessageBuilder};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

const DEFAULT_SYSTEM_ROUTE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SYSTEM_ROUTE_COMMAND_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const DEFAULT_SYSTEM_ROUTE_COMMAND_OUTPUT_MAX_BYTES: usize = 64 * 1024;
const MAX_SYSTEM_ROUTE_COMMAND_OUTPUT_MAX_BYTES: usize = 1024 * 1024;
const SANITIZED_SYSTEM_ROUTE_COMMAND_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const SANITIZED_SYSTEM_ROUTE_COMMAND_LOCALE: &str = "C";
const MAX_LINUX_ROUTE_COMMAND_PROGRAM_BYTES: usize = 4096;
const MAX_LINUX_ROUTE_COMMAND_ARGS: usize = 1024;
const MAX_LINUX_ROUTE_COMMAND_ARG_BYTES: usize = 128 * 1024;
const MAX_LINUX_ROUTE_COMMAND_ARGV_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum RouteManagerError {
    #[error("route manager io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("route manager backend failed: {0}")]
    Backend(String),
    #[error("invalid linux network namespace name: {0}")]
    InvalidNamespace(String),
    #[error("invalid Docker network intent: {0}")]
    InvalidDockerNetworkIntent(String),
    #[error("invalid Kubernetes underlay intent: {0}")]
    InvalidKubernetesUnderlayIntent(String),
    #[error("invalid route plan: {0}")]
    InvalidRoutePlan(String),
    #[error("invalid policy rule: {0}")]
    InvalidPolicyRule(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    pub interface: String,
    pub routes: Vec<Route>,
    pub policy_rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub table: u32,
    pub priority: u32,
    pub from: Option<IpNet>,
    pub to: Option<IpNet>,
    pub fwmark: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxNetworkNamespace {
    name: String,
}

impl LinuxNetworkNamespace {
    pub fn from_name(name: impl Into<String>) -> Result<Self, RouteManagerError> {
        let name = name.into();
        if !is_valid_namespace_name(&name) {
            return Err(RouteManagerError::InvalidNamespace(name));
        }
        Ok(Self { name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> PathBuf {
        PathBuf::from("/var/run/netns").join(&self.name)
    }

    pub fn wrap_program_args(&self, program: &str, args: &[String]) -> (String, Vec<String>) {
        let mut wrapped = Vec::with_capacity(args.len() + 4);
        wrapped.push("netns".to_string());
        wrapped.push("exec".to_string());
        wrapped.push(self.name.clone());
        wrapped.push(program.to_string());
        wrapped.extend(args.iter().cloned());
        ("ip".to_string(), wrapped)
    }
}

fn is_valid_namespace_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !matches!(name, "." | "..")
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

thread_local! {
    static NETLINK_NAMESPACE: RefCell<Option<LinuxNetworkNamespace>> = const { RefCell::new(None) };
}

#[derive(Debug)]
struct NetlinkNamespaceGuard {
    previous: Option<LinuxNetworkNamespace>,
}

impl Drop for NetlinkNamespaceGuard {
    fn drop(&mut self) {
        NETLINK_NAMESPACE.with(|namespace| {
            namespace.replace(self.previous.take());
        });
    }
}

pub fn with_netlink_namespace<T>(
    namespace: Option<&LinuxNetworkNamespace>,
    operation: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let previous = NETLINK_NAMESPACE.with(|current| current.replace(namespace.cloned()));
    let _guard = NetlinkNamespaceGuard { previous };
    operation()
}

#[derive(Debug)]
pub struct LinuxNetlinkSocket {
    socket: AsyncFd<Socket>,
}

impl LinuxNetlinkSocket {
    pub fn from_socket(socket: Socket) -> io::Result<Self> {
        socket.set_non_blocking(true)?;
        Ok(Self {
            socket: AsyncFd::new(socket)?,
        })
    }
}

impl AsyncSocket for LinuxNetlinkSocket {
    fn socket_ref(&self) -> &Socket {
        self.socket.get_ref()
    }

    fn socket_mut(&mut self) -> &mut Socket {
        self.socket.get_mut()
    }

    fn new(protocol: isize) -> io::Result<Self> {
        let namespace = NETLINK_NAMESPACE.with(|current| current.borrow().clone());
        let socket = match namespace {
            Some(namespace) => open_netlink_socket_in_namespace(protocol, &namespace)?,
            None => Socket::new(protocol)?,
        };
        Self::from_socket(socket)
    }

    fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.socket.poll_write_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().send(buf, 0)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &SocketAddr,
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.socket.poll_write_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().send_to(buf, addr, 0)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_recv<B>(&self, cx: &mut Context<'_>, buf: &mut B) -> Poll<io::Result<()>>
    where
        B: bytes::BufMut,
    {
        loop {
            let mut guard = ready!(self.socket.poll_read_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().recv(buf, 0)) {
                Ok(result) => return Poll::Ready(result.map(|_| ())),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_recv_from<B>(&self, cx: &mut Context<'_>, buf: &mut B) -> Poll<io::Result<SocketAddr>>
    where
        B: bytes::BufMut,
    {
        loop {
            let mut guard = ready!(self.socket.poll_read_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().recv_from(buf, 0)) {
                Ok(result) => return Poll::Ready(result.map(|(_len, addr)| addr)),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_recv_from_full(&self, cx: &mut Context<'_>) -> Poll<io::Result<(Vec<u8>, SocketAddr)>> {
        loop {
            let mut guard = ready!(self.socket.poll_read_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().recv_from_full()) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }
}

fn open_netlink_socket_in_namespace(
    protocol: isize,
    namespace: &LinuxNetworkNamespace,
) -> io::Result<Socket> {
    with_linux_network_namespace(Some(namespace), || Socket::new(protocol))
}

pub fn with_linux_network_namespace<T>(
    namespace: Option<&LinuxNetworkNamespace>,
    operation: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let Some(namespace) = namespace else {
        return operation();
    };
    let current_namespace = open_current_thread_netns()?;
    let namespace_path = namespace.path();
    inspect_linux_netns_path(namespace, &namespace_path)?;
    let target_namespace = File::open(&namespace_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to open linux network namespace `{}` at {}: {error}",
                namespace.name(),
                namespace_path.display()
            ),
        )
    })?;
    warn_if_target_netns_is_current(
        namespace,
        &namespace_path,
        &current_namespace,
        &target_namespace,
    )?;

    set_thread_netns(&target_namespace)?;
    let restore_guard = ThreadNetnsRestoreGuard::new(current_namespace);
    let result = operation();
    let restore = restore_guard.restore();

    match (result, restore) {
        (_, Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

struct ThreadNetnsRestoreGuard {
    namespace: File,
    restored: bool,
}

impl ThreadNetnsRestoreGuard {
    fn new(namespace: File) -> Self {
        Self {
            namespace,
            restored: false,
        }
    }

    fn restore(mut self) -> io::Result<()> {
        let result = set_thread_netns(&self.namespace);
        if result.is_ok() {
            self.restored = true;
        }
        result
    }
}

impl Drop for ThreadNetnsRestoreGuard {
    fn drop(&mut self) {
        if !self.restored {
            let _ = set_thread_netns(&self.namespace);
        }
    }
}

fn set_thread_netns(namespace: &File) -> io::Result<()> {
    nix::sched::setns(namespace, CloneFlags::CLONE_NEWNET).map_err(io::Error::from)
}

fn open_current_thread_netns() -> io::Result<File> {
    File::open("/proc/thread-self/ns/net").or_else(|thread_self_error| {
        File::open("/proc/self/ns/net").map_err(|self_error| {
            io::Error::new(
                self_error.kind(),
                format!(
                    "failed to open current thread network namespace at /proc/thread-self/ns/net ({thread_self_error}) or /proc/self/ns/net ({self_error})"
                ),
            )
        })
    })
}

pub fn warn_if_linux_netns_is_current(namespace: &LinuxNetworkNamespace, placement: &'static str) {
    let path = namespace.path();
    match linux_netns_path_matches_current(&path) {
        Ok(true) => {
            tracing::warn!(
                namespace = namespace.name(),
                placement,
                path = %path.display(),
                "configured linux network namespace resolves to the current process namespace"
            );
        }
        Ok(false) => {}
        Err(error) => {
            tracing::debug!(
                %error,
                namespace = namespace.name(),
                placement,
                path = %path.display(),
                "failed to compare configured linux network namespace with the current process namespace"
            );
        }
    }
}

#[cfg(unix)]
fn linux_netns_path_matches_current(path: &Path) -> io::Result<bool> {
    let current_namespace = open_current_thread_netns()?;
    let target_namespace = File::open(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to open linux network namespace at {}: {error}",
                path.display()
            ),
        )
    })?;
    same_file_identity(&current_namespace, &target_namespace)
}

#[cfg(not(unix))]
fn linux_netns_path_matches_current(_path: &Path) -> io::Result<bool> {
    Ok(false)
}

#[cfg(unix)]
fn warn_if_target_netns_is_current(
    namespace: &LinuxNetworkNamespace,
    path: &Path,
    current_namespace: &File,
    target_namespace: &File,
) -> io::Result<()> {
    let current_metadata = current_namespace.metadata().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to stat current thread network namespace: {error}"),
        )
    })?;
    let target_metadata = target_namespace.metadata().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to stat linux network namespace `{}` at {}: {error}",
                namespace.name(),
                path.display()
            ),
        )
    })?;
    if same_file_metadata_identity(&current_metadata, &target_metadata) {
        tracing::warn!(
            namespace = namespace.name(),
            path = %path.display(),
            "configured route-manager linux network namespace resolves to the current process namespace"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn warn_if_target_netns_is_current(
    _namespace: &LinuxNetworkNamespace,
    _path: &Path,
    _current_namespace: &File,
    _target_namespace: &File,
) -> io::Result<()> {
    Ok(())
}

fn inspect_linux_netns_path(namespace: &LinuxNetworkNamespace, path: &Path) -> io::Result<()> {
    let symlink_metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                error.kind(),
                format!(
                    "linux network namespace `{}` does not exist at {}",
                    namespace.name(),
                    path.display()
                ),
            )
        } else {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to inspect linux network namespace `{}` at {}: {error}",
                    namespace.name(),
                    path.display()
                ),
            )
        }
    })?;
    let file_type = symlink_metadata.file_type();
    if file_type.is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "linux network namespace `{}` at {} must not be a symlink",
                namespace.name(),
                path.display()
            ),
        ));
    }
    if file_type.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "linux network namespace `{}` at {} must be a namespace bind mount, not a directory",
                namespace.name(),
                path.display()
            ),
        ));
    }
    ensure_linux_netns_nsfs(namespace, path)
}

#[cfg(target_os = "linux")]
fn ensure_linux_netns_nsfs(namespace: &LinuxNetworkNamespace, path: &Path) -> io::Result<()> {
    let stat = nix::sys::statfs::statfs(path).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "failed to stat filesystem for linux network namespace `{}` at {}: {error}",
                namespace.name(),
                path.display()
            ),
        )
    })?;
    if stat.filesystem_type() == nix::sys::statfs::NSFS_MAGIC {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "linux network namespace `{}` at {} must be an nsfs namespace bind mount",
            namespace.name(),
            path.display()
        ),
    ))
}

#[cfg(not(target_os = "linux"))]
fn ensure_linux_netns_nsfs(_namespace: &LinuxNetworkNamespace, _path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn same_file_metadata_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn same_file_identity(left: &File, right: &File) -> io::Result<bool> {
    let left_metadata = left.metadata()?;
    let right_metadata = right.metadata()?;
    Ok(same_file_metadata_identity(&left_metadata, &right_metadata))
}

fn netlink_namespace_suffix(namespace: Option<&LinuxNetworkNamespace>) -> String {
    namespace
        .map(|namespace| format!(" in linux network namespace `{}`", namespace.name()))
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerNetworkIntent {
    pub container_namespace: String,
    pub host_interface: String,
    pub overlay_interface: String,
    pub container_cidrs: Vec<IpNet>,
    pub expose_host_routes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesUnderlayIntent {
    pub node_name: String,
    pub overlay_interface: String,
    pub api_server_cidrs: Vec<IpNet>,
    pub service_cidrs: Vec<IpNet>,
    pub route_provider: NodeId,
}

#[async_trait]
pub trait RouteManager: Send + Sync {
    async fn apply_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError>;
    async fn remove_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError>;
    async fn apply_docker_intent(
        &self,
        intent: DockerNetworkIntent,
    ) -> Result<RoutePlan, RouteManagerError>;
    async fn apply_kubernetes_intent(
        &self,
        intent: KubernetesUnderlayIntent,
    ) -> Result<RoutePlan, RouteManagerError>;
}

pub fn docker_route_plan(intent: DockerNetworkIntent) -> RoutePlan {
    RoutePlan {
        interface: intent.overlay_interface,
        routes: intent
            .container_cidrs
            .into_iter()
            .enumerate()
            .map(|(index, cidr)| Route {
                id: format!("docker-{index}"),
                cidr,
                advertised_by: NodeId::from_string(intent.container_namespace.clone()),
                via: None,
                metric: 100,
                tags: Default::default(),
            })
            .collect(),
        policy_rules: vec![PolicyRule {
            table: 10_064,
            priority: 10_064,
            from: None,
            to: None,
            fwmark: Some(0x6473),
        }],
    }
}

pub fn checked_docker_route_plan(
    intent: DockerNetworkIntent,
) -> Result<RoutePlan, RouteManagerError> {
    validate_docker_network_intent(&intent)?;
    let plan = docker_route_plan(intent);
    validate_route_plan(&plan)?;
    Ok(plan)
}

pub fn validate_docker_network_intent(
    intent: &DockerNetworkIntent,
) -> Result<(), RouteManagerError> {
    validate_docker_container_namespace(&intent.container_namespace)?;
    validate_linux_interface_name(&intent.host_interface).map_err(invalid_docker_network_intent)?;
    validate_linux_interface_name(&intent.overlay_interface)
        .map_err(invalid_docker_network_intent)?;
    validate_docker_container_cidrs(&intent.container_cidrs)
}

pub fn validate_route_plan(plan: &RoutePlan) -> Result<(), RouteManagerError> {
    validate_linux_interface_name(&plan.interface).map_err(invalid_route_plan)?;
    let mut seen_route_ids = BTreeSet::new();
    let mut seen_routes = BTreeSet::new();
    for route in &plan.routes {
        validate_route_id(&route.id).map_err(invalid_route_plan)?;
        if !seen_route_ids.insert(route.id.as_str()) {
            return Err(invalid_route_plan(format!(
                "route plan must not repeat route ID {}",
                route.id
            )));
        }
        if route.metric == 0 {
            return Err(invalid_route_plan(format!(
                "route {} metric must be greater than zero",
                route.id
            )));
        }
        if let Some(reason) = restricted_route_cidr_reason(&route.cidr) {
            return Err(invalid_route_plan(format!(
                "route {} must not include {reason} CIDR {}",
                route.id, route.cidr
            )));
        }
        let canonical = route.cidr.trunc();
        if route.cidr != canonical {
            return Err(invalid_route_plan(format!(
                "route {} must use canonical CIDR {canonical}, not {}",
                route.id, route.cidr
            )));
        }
        if !seen_routes.insert(route.cidr) {
            return Err(invalid_route_plan(format!(
                "route plan must not repeat CIDR {}",
                route.cidr
            )));
        }
    }
    let mut seen_policy_rules = BTreeSet::new();
    let mut seen_policy_priorities = BTreeSet::new();
    for rule in &plan.policy_rules {
        validate_policy_rule(rule)?;
        let key = (rule.table, rule.priority, rule.from, rule.to, rule.fwmark);
        if !seen_policy_rules.insert(key) {
            return Err(invalid_route_plan(format!(
                "route plan must not repeat policy rule priority {} for table {}",
                rule.priority, rule.table
            )));
        }
        if !seen_policy_priorities.insert(rule.priority) {
            return Err(invalid_route_plan(format!(
                "route plan must not reuse policy rule priority {}",
                rule.priority
            )));
        }
    }
    Ok(())
}

fn validate_route_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("route ID cannot be empty".to_string());
    }
    if id.len() > 128 {
        return Err("route ID exceeds 128 bytes".to_string());
    }
    if matches!(id, "." | "..") {
        return Err("route ID must not be '.' or '..'".to_string());
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(
            "route ID must contain only ASCII letters, digits, '.', '_', ':' or '-'".to_string(),
        );
    }
    Ok(())
}

fn validate_policy_rule(rule: &PolicyRule) -> Result<(), RouteManagerError> {
    if rule.table == 0 {
        return Err(RouteManagerError::InvalidPolicyRule(format!(
            "rule priority {} must use a nonzero routing table",
            rule.priority
        )));
    }
    if rule.priority == 0 {
        return Err(RouteManagerError::InvalidPolicyRule(
            "policy rule priority must be greater than zero".to_string(),
        ));
    }
    if rule.fwmark == Some(0) {
        return Err(RouteManagerError::InvalidPolicyRule(format!(
            "rule priority {} fwmark selector must be nonzero when set",
            rule.priority
        )));
    }
    validate_policy_rule_selector(rule.priority, "from", rule.from)?;
    validate_policy_rule_selector(rule.priority, "to", rule.to)?;
    policy_rule_address_family(rule)?;
    Ok(())
}

fn validate_policy_rule_selector(
    priority: u32,
    label: &'static str,
    selector: Option<IpNet>,
) -> Result<(), RouteManagerError> {
    let Some(cidr) = selector else {
        return Ok(());
    };
    if let Some(reason) = restricted_route_cidr_reason(&cidr) {
        return Err(RouteManagerError::InvalidPolicyRule(format!(
            "rule priority {priority} {label} selector must not include {reason} CIDR {cidr}"
        )));
    }
    let canonical = cidr.trunc();
    if cidr != canonical {
        return Err(RouteManagerError::InvalidPolicyRule(format!(
            "rule priority {priority} {label} selector must use canonical CIDR {canonical}, not {cidr}"
        )));
    }
    Ok(())
}

fn validate_linux_interface_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("linux interface name cannot be empty".to_string());
    }
    if name.len() > 15 {
        return Err(format!("linux interface name `{name}` exceeds 15 bytes"));
    }
    if matches!(name, "." | "..") {
        return Err(format!(
            "linux interface name `{name}` must not be '.' or '..'"
        ));
    }
    if name.starts_with('-') {
        return Err(format!(
            "linux interface name `{name}` must not start with '-'"
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "linux interface name `{name}` must contain only ASCII letters, digits, '.', '_' or '-'"
        ));
    }
    Ok(())
}

fn validate_docker_container_namespace(name: &str) -> Result<(), RouteManagerError> {
    if !is_valid_namespace_name(name) {
        return Err(invalid_docker_network_intent(format!(
            "container namespace `{name}` must be a valid linux network namespace name"
        )));
    }
    Ok(())
}

fn validate_docker_container_cidrs(cidrs: &[IpNet]) -> Result<(), RouteManagerError> {
    let mut seen = BTreeSet::new();
    let mut routes = Vec::new();
    for cidr in cidrs {
        if let Some(reason) = restricted_route_cidr_reason(cidr) {
            return Err(invalid_docker_network_intent(format!(
                "must not include {reason} Docker container CIDR {cidr}"
            )));
        }
        let route = cidr.trunc();
        if cidr != &route {
            return Err(invalid_docker_network_intent(format!(
                "must use canonical Docker container CIDR route {route}, not {cidr}"
            )));
        }
        if !seen.insert(route) {
            return Err(invalid_docker_network_intent(format!(
                "must not repeat Docker container CIDR route {route}"
            )));
        }
        if let Some(overlap) = routes
            .iter()
            .find(|existing| ip_cidrs_overlap(existing, &route))
        {
            return Err(invalid_docker_network_intent(format!(
                "must not include overlapping Docker container CIDR routes {overlap} and {route}"
            )));
        }
        routes.push(route);
    }
    Ok(())
}

fn invalid_docker_network_intent(message: impl Into<String>) -> RouteManagerError {
    RouteManagerError::InvalidDockerNetworkIntent(message.into())
}

fn invalid_route_plan(message: impl Into<String>) -> RouteManagerError {
    RouteManagerError::InvalidRoutePlan(message.into())
}

fn restricted_route_cidr_reason(cidr: &IpNet) -> Option<&'static str> {
    if cidr.prefix_len() == 0 {
        return Some("unrestricted");
    }
    match cidr {
        IpNet::V4(network) => restricted_docker_ipv4_cidr_reason(network),
        IpNet::V6(network) => restricted_docker_ipv6_cidr_reason(network),
    }
}

fn restricted_docker_ipv4_cidr_reason(network: &ipnet::Ipv4Net) -> Option<&'static str> {
    let restricted = [
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(0, 0, 0, 0), 8),
            "unspecified",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8),
            "loopback",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16),
            "link-local",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 4),
            "multicast",
        ),
        (
            ipnet::Ipv4Net::new_assert(Ipv4Addr::new(255, 255, 255, 255), 32),
            "broadcast",
        ),
    ];
    restricted
        .iter()
        .find_map(|(restricted, reason)| ipv4_cidrs_overlap(network, restricted).then_some(*reason))
}

fn restricted_docker_ipv6_cidr_reason(network: &ipnet::Ipv6Net) -> Option<&'static str> {
    let restricted = [
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 128),
            "unspecified",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::LOCALHOST, 128),
            "loopback",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
            "link-local",
        ),
        (
            ipnet::Ipv6Net::new_assert(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
            "multicast",
        ),
    ];
    restricted
        .iter()
        .find_map(|(restricted, reason)| ipv6_cidrs_overlap(network, restricted).then_some(*reason))
}

fn ip_cidrs_overlap(left: &IpNet, right: &IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => ipv4_cidrs_overlap(left, right),
        (IpNet::V6(left), IpNet::V6(right)) => ipv6_cidrs_overlap(left, right),
        _ => false,
    }
}

fn ipv4_cidrs_overlap(left: &ipnet::Ipv4Net, right: &ipnet::Ipv4Net) -> bool {
    left.contains(&right.network())
        || left.contains(&right.broadcast())
        || right.contains(&left.network())
        || right.contains(&left.broadcast())
}

fn ipv6_cidrs_overlap(left: &ipnet::Ipv6Net, right: &ipnet::Ipv6Net) -> bool {
    left.contains(&right.network())
        || left.contains(&right.broadcast())
        || right.contains(&left.network())
        || right.contains(&left.broadcast())
}

pub fn kubernetes_route_plan(intent: KubernetesUnderlayIntent) -> RoutePlan {
    let mut cidrs = intent
        .api_server_cidrs
        .into_iter()
        .chain(intent.service_cidrs)
        .collect::<Vec<_>>();
    cidrs.sort();

    let routes = cidrs
        .into_iter()
        .map(|cidr| Route {
            id: kubernetes_route_id(&cidr),
            cidr,
            advertised_by: intent.route_provider.clone(),
            via: Some(intent.route_provider.clone()),
            metric: 50,
            tags: Default::default(),
        })
        .collect();

    RoutePlan {
        interface: intent.overlay_interface,
        routes,
        policy_rules: vec![PolicyRule {
            table: 10_064,
            priority: 10_050,
            from: None,
            to: None,
            fwmark: None,
        }],
    }
}

fn kubernetes_route_id(cidr: &IpNet) -> String {
    match cidr {
        IpNet::V4(network) => {
            let octets = network.network().octets();
            format!(
                "k8s-v4-{}-{}-{}-{}-{}",
                octets[0],
                octets[1],
                octets[2],
                octets[3],
                network.prefix_len()
            )
        }
        IpNet::V6(network) => {
            let segments = network.network().segments();
            format!(
                "k8s-v6-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{}",
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
                network.prefix_len()
            )
        }
    }
}

pub fn checked_kubernetes_route_plan(
    intent: KubernetesUnderlayIntent,
) -> Result<RoutePlan, RouteManagerError> {
    validate_kubernetes_underlay_intent(&intent)?;
    let plan = kubernetes_route_plan(intent);
    validate_route_plan(&plan)?;
    Ok(plan)
}

pub fn validate_kubernetes_underlay_intent(
    intent: &KubernetesUnderlayIntent,
) -> Result<(), RouteManagerError> {
    validate_linux_interface_name(&intent.overlay_interface)
        .map_err(invalid_kubernetes_underlay_intent)?;
    let mut seen = BTreeSet::new();
    validate_kubernetes_underlay_cidrs(
        "Kubernetes API server CIDR",
        &intent.api_server_cidrs,
        &mut seen,
    )?;
    validate_kubernetes_underlay_cidrs("Kubernetes Service CIDR", &intent.service_cidrs, &mut seen)
}

fn validate_kubernetes_underlay_cidrs(
    label: &str,
    cidrs: &[IpNet],
    seen: &mut BTreeSet<IpNet>,
) -> Result<(), RouteManagerError> {
    for cidr in cidrs {
        if let Some(reason) = restricted_route_cidr_reason(cidr) {
            return Err(invalid_kubernetes_underlay_intent(format!(
                "must not include {reason} {label} {cidr}"
            )));
        }
        let route = cidr.trunc();
        if cidr != &route {
            return Err(invalid_kubernetes_underlay_intent(format!(
                "must use canonical {label} route {route}, not {cidr}"
            )));
        }
        if !seen.insert(route) {
            return Err(invalid_kubernetes_underlay_intent(format!(
                "must not repeat Kubernetes underlay route CIDR {route}"
            )));
        }
    }
    Ok(())
}

fn invalid_kubernetes_underlay_intent(message: impl Into<String>) -> RouteManagerError {
    RouteManagerError::InvalidKubernetesUnderlayIntent(message.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxRouteCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl LinuxRouteCommand {
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn in_namespace(self, namespace: &LinuxNetworkNamespace) -> Self {
        let (program, args) = namespace.wrap_program_args(&self.program, &self.args);
        Self { program, args }
    }
}

#[async_trait]
pub trait LinuxRouteCommandRunner: Send + Sync {
    async fn run(&self, command: LinuxRouteCommand) -> Result<(), RouteManagerError>;
}

#[derive(Debug, Clone, Default)]
pub struct SystemRouteCommandRunner;

#[async_trait]
impl LinuxRouteCommandRunner for SystemRouteCommandRunner {
    async fn run(&self, command: LinuxRouteCommand) -> Result<(), RouteManagerError> {
        run_system_route_command(
            command,
            DEFAULT_SYSTEM_ROUTE_COMMAND_TIMEOUT,
            DEFAULT_SYSTEM_ROUTE_COMMAND_OUTPUT_MAX_BYTES,
        )
        .await
    }
}

#[derive(Debug, Clone)]
pub struct TimedSystemRouteCommandRunner {
    timeout: Duration,
    output_max_bytes: usize,
}

impl TimedSystemRouteCommandRunner {
    pub fn new(timeout: Duration) -> Self {
        Self::with_output_max_bytes(timeout, DEFAULT_SYSTEM_ROUTE_COMMAND_OUTPUT_MAX_BYTES)
    }

    pub fn with_output_max_bytes(timeout: Duration, output_max_bytes: usize) -> Self {
        Self {
            timeout,
            output_max_bytes,
        }
    }
}

impl Default for TimedSystemRouteCommandRunner {
    fn default() -> Self {
        Self::new(DEFAULT_SYSTEM_ROUTE_COMMAND_TIMEOUT)
    }
}

#[async_trait]
impl LinuxRouteCommandRunner for TimedSystemRouteCommandRunner {
    async fn run(&self, command: LinuxRouteCommand) -> Result<(), RouteManagerError> {
        run_system_route_command(command, self.timeout, self.output_max_bytes).await
    }
}

async fn run_system_route_command(
    command: LinuxRouteCommand,
    timeout: Duration,
    output_max_bytes: usize,
) -> Result<(), RouteManagerError> {
    validate_system_route_command_runtime_bounds(timeout, output_max_bytes)?;
    validate_linux_route_command(&command)?;
    let command_label = command_label(&command.program, &command.args);
    let output =
        run_route_command_output(command, timeout, output_max_bytes, &command_label).await?;
    if output.status.success() {
        return Ok(());
    }

    Err(RouteManagerError::Backend(format!(
        "{command_label} failed: {}",
        command_stderr_message(&output.stderr)
    )))
}

fn validate_system_route_command_runtime_bounds(
    timeout: Duration,
    output_max_bytes: usize,
) -> Result<(), RouteManagerError> {
    if timeout.is_zero() {
        return Err(RouteManagerError::Backend(
            "invalid linux route command runtime bounds: timeout must be greater than zero"
                .to_string(),
        ));
    }
    if timeout > MAX_SYSTEM_ROUTE_COMMAND_TIMEOUT {
        return Err(RouteManagerError::Backend(format!(
            "invalid linux route command runtime bounds: timeout must not exceed {}s",
            MAX_SYSTEM_ROUTE_COMMAND_TIMEOUT.as_secs()
        )));
    }
    if output_max_bytes == 0 {
        return Err(RouteManagerError::Backend(
            "invalid linux route command runtime bounds: output_max_bytes must be greater than zero"
                .to_string(),
        ));
    }
    if output_max_bytes > MAX_SYSTEM_ROUTE_COMMAND_OUTPUT_MAX_BYTES {
        return Err(RouteManagerError::Backend(format!(
            "invalid linux route command runtime bounds: output_max_bytes must not exceed {MAX_SYSTEM_ROUTE_COMMAND_OUTPUT_MAX_BYTES}"
        )));
    }
    Ok(())
}

fn validate_linux_route_command(command: &LinuxRouteCommand) -> Result<(), RouteManagerError> {
    validate_linux_route_command_program(&command.program)?;
    if command.args.len() > MAX_LINUX_ROUTE_COMMAND_ARGS {
        return Err(RouteManagerError::Backend(format!(
            "invalid linux route command: too many arguments: {} > {MAX_LINUX_ROUTE_COMMAND_ARGS}",
            command.args.len()
        )));
    }

    let mut total_bytes = command.program.len();
    for (index, arg) in command.args.iter().enumerate() {
        if arg.len() > MAX_LINUX_ROUTE_COMMAND_ARG_BYTES {
            return Err(RouteManagerError::Backend(format!(
                "invalid linux route command: argument {index} exceeds {MAX_LINUX_ROUTE_COMMAND_ARG_BYTES} bytes"
            )));
        }
        if arg.as_bytes().contains(&0) {
            return Err(RouteManagerError::Backend(format!(
                "invalid linux route command: argument {index} must not contain NUL bytes"
            )));
        }
        total_bytes = total_bytes.saturating_add(arg.len());
        if total_bytes > MAX_LINUX_ROUTE_COMMAND_ARGV_BYTES {
            return Err(RouteManagerError::Backend(format!(
                "invalid linux route command: argv exceeds {MAX_LINUX_ROUTE_COMMAND_ARGV_BYTES} bytes"
            )));
        }
    }

    Ok(())
}

fn validate_linux_route_command_program(program: &str) -> Result<(), RouteManagerError> {
    if program.is_empty() {
        return Err(RouteManagerError::Backend(
            "invalid linux route command: program cannot be empty".to_string(),
        ));
    }
    if program.len() > MAX_LINUX_ROUTE_COMMAND_PROGRAM_BYTES {
        return Err(RouteManagerError::Backend(format!(
            "invalid linux route command: program exceeds {MAX_LINUX_ROUTE_COMMAND_PROGRAM_BYTES} bytes"
        )));
    }
    if program.as_bytes().contains(&0) {
        return Err(RouteManagerError::Backend(
            "invalid linux route command: program must not contain NUL bytes".to_string(),
        ));
    }
    if program.chars().any(char::is_control) {
        return Err(RouteManagerError::Backend(
            "invalid linux route command: program must not contain control characters".to_string(),
        ));
    }
    if program.chars().any(char::is_whitespace) {
        return Err(RouteManagerError::Backend(
            "invalid linux route command: program must not contain whitespace".to_string(),
        ));
    }

    let program_name = if program.contains('/') {
        let program_path = Path::new(program);
        if !program_path.is_absolute() {
            return Err(RouteManagerError::Backend(
                "invalid linux route command: program must be a bare command name or an absolute path"
                    .to_string(),
            ));
        }
        if program
            .split('/')
            .any(|component| matches!(component, "." | ".."))
        {
            return Err(RouteManagerError::Backend(
                "invalid linux route command: program path must not contain '.' or '..' components"
                    .to_string(),
            ));
        }
        program_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                RouteManagerError::Backend(
                    "invalid linux route command: program path must name an executable".to_string(),
                )
            })?
    } else {
        program
    };
    if matches!(program_name, "." | "..") {
        return Err(RouteManagerError::Backend(
            "invalid linux route command: program name must not be '.' or '..'".to_string(),
        ));
    }
    if program_name.starts_with('-') {
        return Err(RouteManagerError::Backend(
            "invalid linux route command: program name must not start with '-'".to_string(),
        ));
    }

    Ok(())
}

fn resolve_trusted_linux_route_command_paths(
    mut command: LinuxRouteCommand,
) -> Result<LinuxRouteCommand, RouteManagerError> {
    let original_program = command.program.clone();
    let resolved_program = resolve_trusted_linux_route_command_program(&command.program)?;
    command.program = route_command_path_to_string(&resolved_program)?;

    if linux_route_command_program_name(&original_program) == Some("ip")
        && command.args.len() >= 4
        && command.args[0] == "netns"
        && command.args[1] == "exec"
    {
        validate_linux_route_command_program(&command.args[3])?;
        let resolved_inner = resolve_trusted_linux_route_command_program(&command.args[3])?;
        command.args[3] = route_command_path_to_string(&resolved_inner)?;
    }

    Ok(command)
}

fn resolve_trusted_linux_route_command_program(
    program: &str,
) -> Result<PathBuf, RouteManagerError> {
    if program.contains('/') {
        return ensure_trusted_linux_route_command_executable(
            Path::new(program),
            "linux route command program",
        );
    }

    for directory in std::env::split_paths(OsStr::new(SANITIZED_SYSTEM_ROUTE_COMMAND_PATH)) {
        if directory.as_os_str().is_empty() || !directory.is_absolute() {
            return Err(RouteManagerError::Backend(format!(
                "invalid linux route command PATH entry `{}`: expected an absolute directory",
                directory.display()
            )));
        }
        if route_command_path_has_special_component(&directory) {
            return Err(RouteManagerError::Backend(format!(
                "invalid linux route command PATH entry `{}`: must not contain '.' or '..' components",
                directory.display()
            )));
        }
        if let Err(error) = ensure_trusted_linux_route_command_search_directory(&directory) {
            if !matches!(&error, RouteManagerError::Io(io) if io.kind() == std::io::ErrorKind::NotFound)
            {
                return Err(error);
            }
            continue;
        }

        let candidate = directory.join(program);
        match candidate.symlink_metadata() {
            Ok(_) => {
                return ensure_trusted_linux_route_command_executable(
                    &candidate,
                    "linux route command program",
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(RouteManagerError::Io(error)),
        }
    }

    Err(RouteManagerError::Backend(format!(
        "missing linux route command program `{program}` in sanitized PATH"
    )))
}

fn route_command_path_to_string(path: &Path) -> Result<String, RouteManagerError> {
    path.to_str().map(ToOwned::to_owned).ok_or_else(|| {
        RouteManagerError::Backend(format!(
            "resolved linux route command path {} is not UTF-8",
            path.display()
        ))
    })
}

fn linux_route_command_program_name(program: &str) -> Option<&str> {
    if program.contains('/') {
        Path::new(program)
            .file_name()
            .and_then(|name| name.to_str())
    } else {
        Some(program)
    }
}

fn route_command_path_has_special_component(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    })
}

#[cfg(unix)]
fn ensure_trusted_linux_route_command_search_directory(
    directory: &Path,
) -> Result<(), RouteManagerError> {
    let metadata = std::fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() {
        return Err(RouteManagerError::Backend(format!(
            "linux route command PATH entry {} must not be a symlink",
            directory.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(RouteManagerError::Backend(format!(
            "linux route command PATH entry {} must be a directory",
            directory.display()
        )));
    }
    ensure_trusted_linux_route_command_directory_chain(directory, "linux route command PATH entry")
}

#[cfg(not(unix))]
fn ensure_trusted_linux_route_command_search_directory(
    directory: &Path,
) -> Result<(), RouteManagerError> {
    let metadata = std::fs::metadata(directory)?;
    if !metadata.is_dir() {
        return Err(RouteManagerError::Backend(format!(
            "linux route command PATH entry {} must be a directory",
            directory.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_trusted_linux_route_command_executable(
    path: &Path,
    label: &str,
) -> Result<PathBuf, RouteManagerError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(RouteManagerError::Backend(format!(
            "{label} at {} must not be a symlink",
            path.display()
        )));
    }
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || mode & 0o111 == 0 {
        return Err(RouteManagerError::Backend(format!(
            "{label} at {} expected an executable regular file",
            path.display()
        )));
    }
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    ensure_trusted_linux_route_command_owner(label, "at", path, metadata.uid(), effective_uid)?;
    if mode & 0o022 != 0 {
        return Err(RouteManagerError::Backend(format!(
            "{label} at {} must not be group- or world-writable",
            path.display()
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        RouteManagerError::Backend(format!(
            "failed to locate parent directory for {label} at {}",
            path.display()
        ))
    })?;
    ensure_trusted_linux_route_command_directory_chain(parent, label)?;
    Ok(path.to_path_buf())
}

#[cfg(not(unix))]
fn ensure_trusted_linux_route_command_executable(
    path: &Path,
    label: &str,
) -> Result<PathBuf, RouteManagerError> {
    let canonical = std::fs::canonicalize(path)?;
    let metadata = std::fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(RouteManagerError::Backend(format!(
            "{label} at {} expected an executable regular file",
            path.display()
        )));
    }
    Ok(canonical)
}

#[cfg(unix)]
fn ensure_trusted_linux_route_command_directory_chain(
    directory: &Path,
    label: &str,
) -> Result<(), RouteManagerError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let effective_uid = nix::unistd::Uid::effective().as_raw();
    let mut current = PathBuf::new();
    for component in directory.components() {
        match component {
            std::path::Component::RootDir => current.push(component.as_os_str()),
            std::path::Component::Normal(part) => {
                current.push(part);
                let metadata = std::fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() {
                    return Err(RouteManagerError::Backend(format!(
                        "{label} parent {} must not be a symlink",
                        current.display()
                    )));
                }
                if !metadata.is_dir() {
                    return Err(RouteManagerError::Backend(format!(
                        "{label} parent {} must be a directory",
                        current.display()
                    )));
                }
                ensure_trusted_linux_route_command_owner(
                    label,
                    "parent",
                    &current,
                    metadata.uid(),
                    effective_uid,
                )?;
                if metadata.permissions().mode() & 0o022 != 0 {
                    return Err(RouteManagerError::Backend(format!(
                        "{label} parent {} must not be group- or world-writable",
                        current.display()
                    )));
                }
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(RouteManagerError::Backend(format!(
                    "{label} parent {} must not contain '..' components",
                    directory.display()
                )));
            }
            std::path::Component::Prefix(prefix) => current.push(prefix.as_os_str()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_trusted_linux_route_command_owner(
    label: &str,
    relationship: &str,
    path: &Path,
    owner_uid: u32,
    effective_uid: u32,
) -> Result<(), RouteManagerError> {
    if owner_uid != 0 && owner_uid != effective_uid {
        return Err(RouteManagerError::Backend(format!(
            "{label} {relationship} {} must be owned by root or the current effective user",
            path.display()
        )));
    }
    Ok(())
}

async fn run_route_command_output(
    command: LinuxRouteCommand,
    timeout: Duration,
    output_max_bytes: usize,
    command_label: &str,
) -> Result<BoundedRouteCommandOutput, RouteManagerError> {
    collect_bounded_route_command_output(command, timeout, output_max_bytes, command_label).await
}

async fn collect_bounded_route_command_output(
    command: LinuxRouteCommand,
    timeout: Duration,
    output_max_bytes: usize,
    command_label: &str,
) -> Result<BoundedRouteCommandOutput, RouteManagerError> {
    let command = resolve_trusted_linux_route_command_paths(command)?;
    let mut child_command = Command::new(&command.program);
    child_command
        .args(&command.args)
        .env_clear()
        .env("PATH", SANITIZED_SYSTEM_ROUTE_COMMAND_PATH)
        .env("LANG", SANITIZED_SYSTEM_ROUTE_COMMAND_LOCALE)
        .env("LC_ALL", SANITIZED_SYSTEM_ROUTE_COMMAND_LOCALE)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_route_command_process_group(&mut child_command);

    let mut child = child_command.spawn().map_err(RouteManagerError::Io)?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| RouteManagerError::Io(io::Error::other("child stdout was not piped")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| RouteManagerError::Io(io::Error::other("child stderr was not piped")))?;

    let stdout_task = tokio::spawn(read_limited_route_command_output(stdout, output_max_bytes));
    let stderr_task = tokio::spawn(read_limited_route_command_output(stderr, output_max_bytes));

    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            stdout_task.abort();
            stderr_task.abort();
            return Err(RouteManagerError::Io(error));
        }
        Err(_) => {
            let kill_error = kill_timed_out_route_child(&mut child);
            let _ = child.wait().await;
            stdout_task.abort();
            stderr_task.abort();
            let mut message = format!(
                "{command_label} timed out after {}",
                command_timeout_label(timeout)
            );
            if let Some(error) = kill_error {
                message.push_str(&format!("; failed to kill timed-out child: {error}"));
            }
            return Err(RouteManagerError::Backend(message));
        }
    };

    let _stdout = collect_route_command_output_task(stdout_task).await?;
    let stderr = collect_route_command_output_task(stderr_task).await?;

    Ok(BoundedRouteCommandOutput { status, stderr })
}

fn configure_route_command_process_group(_command: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        _command.process_group(0);
    }
}

fn kill_timed_out_route_child(child: &mut tokio::process::Child) -> Option<String> {
    #[cfg(target_os = "linux")]
    if let Some(pid) = child.id() {
        match kill_route_process_group(pid) {
            Ok(()) => return None,
            Err(error) if error.raw_os_error() == Some(nix::libc::ESRCH) => return None,
            Err(group_error) => {
                return match child.start_kill() {
                    Ok(()) => Some(format!(
                        "process group {pid}: {group_error}; direct child kill succeeded"
                    )),
                    Err(child_error) => Some(format!(
                        "process group {pid}: {group_error}; direct child: {child_error}"
                    )),
                };
            }
        }
    }

    child.start_kill().err().map(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn kill_route_process_group(pid: u32) -> io::Result<()> {
    let pgid: i32 = i32::try_from(pid)
        .map_err(|_| io::Error::other(format!("child pid {pid} exceeds pid_t range")))?;
    nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(pgid),
        nix::sys::signal::Signal::SIGKILL,
    )
    .map_err(|error| io::Error::from_raw_os_error(error as i32))
}

async fn collect_route_command_output_task(
    task: tokio::task::JoinHandle<io::Result<LimitedRouteCommandOutput>>,
) -> Result<LimitedRouteCommandOutput, RouteManagerError> {
    match task.await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(RouteManagerError::Io(error)),
        Err(error) => Err(RouteManagerError::Backend(format!(
            "route command output reader failed: {error}"
        ))),
    }
}

#[derive(Debug)]
struct BoundedRouteCommandOutput {
    status: ExitStatus,
    stderr: LimitedRouteCommandOutput,
}

#[derive(Debug)]
struct LimitedRouteCommandOutput {
    bytes: Vec<u8>,
    truncated: bool,
    limit: usize,
}

async fn read_limited_route_command_output<R>(
    mut reader: R,
    limit: usize,
) -> io::Result<LimitedRouteCommandOutput>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(limit.min(4096));
    let mut truncated = false;
    let mut chunk = [0_u8; 4096];

    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            break;
        }

        let remaining = limit.saturating_sub(bytes.len());
        if remaining > 0 {
            let keep = read.min(remaining);
            bytes.extend_from_slice(&chunk[..keep]);
            if keep < read {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }

    Ok(LimitedRouteCommandOutput {
        bytes,
        truncated,
        limit,
    })
}

fn command_stderr_message(stderr: &LimitedRouteCommandOutput) -> String {
    let text = command_diagnostic_component(String::from_utf8_lossy(&stderr.bytes).trim());
    if !stderr.truncated {
        return text;
    }

    let suffix = format!("stderr truncated after {} bytes", stderr.limit);
    if text.is_empty() {
        suffix
    } else {
        format!("{text} ({suffix})")
    }
}

fn command_timeout_label(timeout: Duration) -> String {
    if timeout.as_millis() < 1000 {
        format!("{}ms", timeout.as_millis())
    } else {
        format!("{}s", timeout.as_secs())
    }
}

fn command_label(program: &str, args: &[String]) -> String {
    let program = command_diagnostic_component(program);
    if args.is_empty() {
        program
    } else {
        let args = args
            .iter()
            .map(|arg| command_diagnostic_component(arg))
            .collect::<Vec<_>>()
            .join(" ");
        format!("{program} {args}")
    }
}

fn command_diagnostic_component(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

#[derive(Debug, Clone)]
pub struct NamespacedLinuxRouteCommandRunner<R> {
    namespace: LinuxNetworkNamespace,
    inner: R,
}

impl<R> NamespacedLinuxRouteCommandRunner<R> {
    pub fn new(namespace: LinuxNetworkNamespace, inner: R) -> Self {
        Self { namespace, inner }
    }
}

#[async_trait]
impl<R> LinuxRouteCommandRunner for NamespacedLinuxRouteCommandRunner<R>
where
    R: LinuxRouteCommandRunner,
{
    async fn run(&self, command: LinuxRouteCommand) -> Result<(), RouteManagerError> {
        warn_if_linux_netns_is_current(&self.namespace, "route command runner");
        self.inner.run(command.in_namespace(&self.namespace)).await
    }
}

#[derive(Debug, Clone)]
pub struct LinuxRouteManager<R> {
    runner: R,
}

impl<R> LinuxRouteManager<R>
where
    R: LinuxRouteCommandRunner,
{
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    fn route_tables(plan: &RoutePlan) -> Vec<Option<u32>> {
        let tables = plan
            .policy_rules
            .iter()
            .map(|rule| rule.table)
            .collect::<BTreeSet<_>>();
        if tables.is_empty() {
            vec![None]
        } else {
            tables.into_iter().map(Some).collect()
        }
    }

    fn apply_route_commands(plan: &RoutePlan) -> Vec<LinuxRouteCommand> {
        let mut commands = Vec::new();
        for table in Self::route_tables(plan) {
            for route in &plan.routes {
                commands.push(Self::route_command("replace", plan, route, table));
            }
        }
        commands
    }

    fn remove_route_commands(plan: &RoutePlan) -> Vec<LinuxRouteCommand> {
        let mut commands = Vec::new();
        for table in Self::route_tables(plan) {
            for route in &plan.routes {
                commands.push(Self::route_command("del", plan, route, table));
            }
        }
        commands
    }

    fn route_command(
        action: &str,
        plan: &RoutePlan,
        route: &Route,
        table: Option<u32>,
    ) -> LinuxRouteCommand {
        let mut args = vec![
            "route".to_string(),
            action.to_string(),
            route.cidr.to_string(),
            "dev".to_string(),
            plan.interface.clone(),
        ];
        if let Some(table) = table {
            args.push("table".to_string());
            args.push(table.to_string());
        }
        if action == "replace" {
            args.push("metric".to_string());
            args.push(route.metric.to_string());
        }
        LinuxRouteCommand::new("ip", args)
    }

    fn policy_rule_command(action: &str, rule: &PolicyRule) -> LinuxRouteCommand {
        let mut args = vec![
            "rule".to_string(),
            action.to_string(),
            "priority".to_string(),
            rule.priority.to_string(),
        ];
        if let Some(from) = rule.from {
            args.push("from".to_string());
            args.push(from.to_string());
        }
        if let Some(to) = rule.to {
            args.push("to".to_string());
            args.push(to.to_string());
        }
        if let Some(fwmark) = rule.fwmark {
            args.push("fwmark".to_string());
            args.push(format!("0x{fwmark:x}"));
        }
        args.push("table".to_string());
        args.push(rule.table.to_string());
        LinuxRouteCommand::new("ip", args)
    }
}

#[async_trait]
impl<R> RouteManager for LinuxRouteManager<R>
where
    R: LinuxRouteCommandRunner,
{
    async fn apply_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
        validate_route_plan(&plan)?;
        for command in Self::apply_route_commands(&plan) {
            self.runner.run(command).await?;
        }
        for rule in &plan.policy_rules {
            let _ = self
                .runner
                .run(Self::policy_rule_command("del", rule))
                .await;
            self.runner
                .run(Self::policy_rule_command("add", rule))
                .await?;
        }
        Ok(())
    }

    async fn remove_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
        validate_route_plan(&plan)?;
        for rule in &plan.policy_rules {
            self.runner
                .run(Self::policy_rule_command("del", rule))
                .await?;
        }
        for command in Self::remove_route_commands(&plan) {
            self.runner.run(command).await?;
        }
        Ok(())
    }

    async fn apply_docker_intent(
        &self,
        intent: DockerNetworkIntent,
    ) -> Result<RoutePlan, RouteManagerError> {
        let plan = checked_docker_route_plan(intent)?;
        self.apply_routes(plan.clone()).await?;
        Ok(plan)
    }

    async fn apply_kubernetes_intent(
        &self,
        intent: KubernetesUnderlayIntent,
    ) -> Result<RoutePlan, RouteManagerError> {
        let plan = checked_kubernetes_route_plan(intent)?;
        self.apply_routes(plan.clone()).await?;
        Ok(plan)
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinuxNetlinkRouteManager {
    namespace: Option<LinuxNetworkNamespace>,
}

impl LinuxNetlinkRouteManager {
    pub fn new() -> Self {
        Self { namespace: None }
    }

    pub fn new_in_namespace(namespace: LinuxNetworkNamespace) -> Self {
        Self {
            namespace: Some(namespace),
        }
    }

    pub fn namespace(&self) -> Option<&LinuxNetworkNamespace> {
        self.namespace.as_ref()
    }

    async fn open_handle(&self) -> Result<Handle, RouteManagerError> {
        let (connection, handle, _) = with_netlink_namespace(self.namespace.as_ref(), || {
            rtnetlink::new_connection_with_socket::<LinuxNetlinkSocket>()
        })
        .map_err(|error| {
            RouteManagerError::Backend(format!(
                "failed to open route netlink connection{}: {error}",
                netlink_namespace_suffix(self.namespace.as_ref())
            ))
        })?;
        tokio::spawn(connection);
        Ok(handle)
    }

    async fn interface_index(handle: &Handle, interface: &str) -> Result<u32, RouteManagerError> {
        let mut links = handle
            .link()
            .get()
            .match_name(interface.to_string())
            .execute();
        let link = links.try_next().await.map_err(|error| {
            RouteManagerError::Backend(format!(
                "failed to query interface `{interface}` through rtnetlink: {error}"
            ))
        })?;
        link.map(|link| link.header.index).ok_or_else(|| {
            RouteManagerError::Backend(format!(
                "interface `{interface}` was not found for route netlink backend"
            ))
        })
    }

    async fn replace_route(
        handle: &Handle,
        route: &Route,
        interface_index: u32,
        table: Option<u32>,
    ) -> Result<(), RouteManagerError> {
        handle
            .route()
            .add(netlink_route_message(route, interface_index, table))
            .replace()
            .execute()
            .await
            .map_err(|error| {
                RouteManagerError::Backend(format!(
                    "failed to replace route {} through rtnetlink: {error}",
                    route.cidr
                ))
            })
    }

    async fn delete_route(
        handle: &Handle,
        route: &Route,
        interface_index: u32,
        table: Option<u32>,
    ) -> Result<(), RouteManagerError> {
        handle
            .route()
            .del(netlink_route_message(route, interface_index, table))
            .execute()
            .await
            .map_err(|error| {
                RouteManagerError::Backend(format!(
                    "failed to delete route {} through rtnetlink: {error}",
                    route.cidr
                ))
            })
    }

    async fn add_rule(handle: &Handle, rule: &PolicyRule) -> Result<(), RouteManagerError> {
        let mut request = handle.rule().add();
        request
            .message_mut()
            .clone_from(&netlink_rule_message(rule)?);
        request.execute().await.map_err(|error| {
            RouteManagerError::Backend(format!(
                "failed to add policy rule priority {} through rtnetlink: {error}",
                rule.priority
            ))
        })
    }

    async fn delete_rule(handle: &Handle, rule: &PolicyRule) -> Result<(), RouteManagerError> {
        handle
            .rule()
            .del(netlink_rule_message(rule)?)
            .execute()
            .await
            .map_err(|error| {
                RouteManagerError::Backend(format!(
                    "failed to delete policy rule priority {} through rtnetlink: {error}",
                    rule.priority
                ))
            })
    }
}

#[async_trait]
impl RouteManager for LinuxNetlinkRouteManager {
    async fn apply_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
        validate_route_plan(&plan)?;
        let handle = self.open_handle().await?;
        let interface_index = Self::interface_index(&handle, &plan.interface).await?;
        for table in LinuxRouteManager::<SystemRouteCommandRunner>::route_tables(&plan) {
            for route in &plan.routes {
                Self::replace_route(&handle, route, interface_index, table).await?;
            }
        }
        for rule in &plan.policy_rules {
            let _ = Self::delete_rule(&handle, rule).await;
            Self::add_rule(&handle, rule).await?;
        }
        Ok(())
    }

    async fn remove_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
        validate_route_plan(&plan)?;
        let handle = self.open_handle().await?;
        let interface_index = Self::interface_index(&handle, &plan.interface).await?;
        for rule in &plan.policy_rules {
            Self::delete_rule(&handle, rule).await?;
        }
        for table in LinuxRouteManager::<SystemRouteCommandRunner>::route_tables(&plan) {
            for route in &plan.routes {
                Self::delete_route(&handle, route, interface_index, table).await?;
            }
        }
        Ok(())
    }

    async fn apply_docker_intent(
        &self,
        intent: DockerNetworkIntent,
    ) -> Result<RoutePlan, RouteManagerError> {
        let plan = checked_docker_route_plan(intent)?;
        self.apply_routes(plan.clone()).await?;
        Ok(plan)
    }

    async fn apply_kubernetes_intent(
        &self,
        intent: KubernetesUnderlayIntent,
    ) -> Result<RoutePlan, RouteManagerError> {
        let plan = checked_kubernetes_route_plan(intent)?;
        self.apply_routes(plan.clone()).await?;
        Ok(plan)
    }
}

fn netlink_route_message(route: &Route, interface_index: u32, table: Option<u32>) -> RouteMessage {
    match route.cidr {
        IpNet::V4(network) => {
            let mut builder = RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                .destination_prefix(network.addr(), network.prefix_len())
                .output_interface(interface_index)
                .priority(route.metric);
            if let Some(table) = table {
                builder = builder.table_id(table);
            }
            builder.build()
        }
        IpNet::V6(network) => {
            let mut builder = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
                .destination_prefix(network.addr(), network.prefix_len())
                .output_interface(interface_index)
                .priority(route.metric);
            if let Some(table) = table {
                builder = builder.table_id(table);
            }
            builder.build()
        }
    }
}

fn netlink_rule_message(rule: &PolicyRule) -> Result<RuleMessage, RouteManagerError> {
    let mut message = RuleMessage::default();
    message.header.family = policy_rule_address_family(rule)?;
    message.header.action = RuleAction::ToTable;
    if rule.table > u8::MAX as u32 {
        message.attributes.push(RuleAttribute::Table(rule.table));
    } else {
        message.header.table = rule.table as u8;
    }
    message
        .attributes
        .push(RuleAttribute::Priority(rule.priority));
    if let Some(from) = rule.from {
        message.header.src_len = from.prefix_len();
        message.attributes.push(RuleAttribute::Source(from.addr()));
    }
    if let Some(to) = rule.to {
        message.header.dst_len = to.prefix_len();
        message
            .attributes
            .push(RuleAttribute::Destination(to.addr()));
    }
    if let Some(fwmark) = rule.fwmark {
        message.attributes.push(RuleAttribute::FwMark(fwmark));
    }
    Ok(message)
}

fn policy_rule_address_family(rule: &PolicyRule) -> Result<AddressFamily, RouteManagerError> {
    let mut family = None;
    for network in rule.from.into_iter().chain(rule.to) {
        let network_family = match network.addr() {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };
        match family {
            Some(existing) if existing != network_family => {
                return Err(RouteManagerError::InvalidPolicyRule(format!(
                    "rule priority {} mixes IPv4 and IPv6 selectors",
                    rule.priority
                )));
            }
            Some(_) => {}
            None => family = Some(network_family),
        }
    }
    Ok(family.unwrap_or(AddressFamily::Unspec))
}

#[derive(Debug, Clone)]
pub struct DryRunLinuxRouteManager;

#[async_trait]
impl RouteManager for DryRunLinuxRouteManager {
    async fn apply_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
        validate_route_plan(&plan)?;
        Ok(())
    }

    async fn remove_routes(&self, plan: RoutePlan) -> Result<(), RouteManagerError> {
        validate_route_plan(&plan)?;
        Ok(())
    }

    async fn apply_docker_intent(
        &self,
        intent: DockerNetworkIntent,
    ) -> Result<RoutePlan, RouteManagerError> {
        checked_docker_route_plan(intent)
    }

    async fn apply_kubernetes_intent(
        &self,
        intent: KubernetesUnderlayIntent,
    ) -> Result<RoutePlan, RouteManagerError> {
        checked_kubernetes_route_plan(intent)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct RecordingRunner {
        commands: Arc<tokio::sync::RwLock<Vec<LinuxRouteCommand>>>,
        fail_rule_delete: bool,
    }

    impl RecordingRunner {
        fn with_failed_rule_delete() -> Self {
            Self {
                fail_rule_delete: true,
                ..Self::default()
            }
        }

        async fn commands(&self) -> Vec<LinuxRouteCommand> {
            self.commands.read().await.clone()
        }
    }

    #[async_trait]
    impl LinuxRouteCommandRunner for RecordingRunner {
        async fn run(&self, command: LinuxRouteCommand) -> Result<(), RouteManagerError> {
            let should_fail_rule_delete = self.fail_rule_delete
                && command.program == "ip"
                && command
                    .args
                    .iter()
                    .map(String::as_str)
                    .take(2)
                    .eq(["rule", "del"]);
            self.commands.write().await.push(command);
            if should_fail_rule_delete {
                Err(RouteManagerError::Backend("rule missing".to_string()))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(unix)]
    fn trusted_route_test_shell() -> String {
        for candidate in ["/usr/bin/dash", "/usr/bin/bash", "/bin/dash", "/bin/bash"] {
            if ensure_trusted_linux_route_command_executable(Path::new(candidate), "test shell")
                .is_ok()
            {
                return candidate.to_string();
            }
        }
        panic!("trusted non-symlink test shell was not found");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_route_command_runner_reports_failure_stderr() {
        let runner = TimedSystemRouteCommandRunner::new(Duration::from_secs(1));
        let shell = trusted_route_test_shell();
        let error = match runner
            .run(LinuxRouteCommand::new(
                shell,
                ["-c", "echo route-failed >&2; exit 7"],
            ))
            .await
        {
            Ok(()) => panic!("command should fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("route-failed"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_route_command_runner_uses_sanitized_environment() {
        let runner = TimedSystemRouteCommandRunner::new(Duration::from_secs(1));
        let shell = trusted_route_test_shell();
        let script = r#"test "${PATH:-}" = "/usr/sbin:/usr/bin:/sbin:/bin" && test "${LANG:-}" = "C" && test "${LC_ALL:-}" = "C" && test -z "${HOME+x}" && test -z "${LD_PRELOAD+x}""#;

        match runner
            .run(LinuxRouteCommand::new(shell, ["-c", script]))
            .await
        {
            Ok(()) => {}
            Err(error) => panic!("route command environment should be sanitized: {error}"),
        }
    }

    #[test]
    fn route_command_label_escapes_control_characters() {
        let label = command_label(
            "ip",
            &[
                "route\nreplace".to_string(),
                "table\t100".to_string(),
                r"via\peer".to_string(),
            ],
        );

        assert_eq!(label, r"ip route\nreplace table\t100 via\\peer");
        assert!(!label.contains('\n'));
        assert!(!label.contains('\t'));
    }

    #[test]
    fn route_command_stderr_message_escapes_control_characters() {
        let stderr = LimitedRouteCommandOutput {
            bytes: b"failed\nstderr\tfield".to_vec(),
            truncated: false,
            limit: 64,
        };

        let message = command_stderr_message(&stderr);

        assert_eq!(message, r"failed\nstderr\tfield");
        assert!(!message.contains('\n'));
        assert!(!message.contains('\t'));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_route_command_runner_rejects_invalid_command_vectors() {
        let runner = TimedSystemRouteCommandRunner::new(Duration::from_secs(1));

        let error = match runner.run(LinuxRouteCommand::new("", ["route"])).await {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("program cannot be empty"));

        for (program, expected) in [
            ("ip\0bad", "program must not contain NUL bytes"),
            ("ip\nbad", "program must not contain control characters"),
            ("ip bad", "program must not contain whitespace"),
            (
                "./ip",
                "program must be a bare command name or an absolute path",
            ),
            ("/usr/bin/./ip", "program path must not contain"),
            ("/usr/bin/../ip", "program path must not contain"),
            ("/", "program path must name an executable"),
            (".", "program name must not be '.' or '..'"),
            ("..", "program name must not be '.' or '..'"),
            ("-ip", "program name must not start with '-'"),
            ("/tmp/-ip", "program name must not start with '-'"),
        ] {
            let error = match runner.run(LinuxRouteCommand::new(program, ["route"])).await {
                Ok(()) => panic!("command should be rejected"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "unexpected error for {program:?}: {error}"
            );
        }

        let error = match runner
            .run(LinuxRouteCommand::new("ip", ["route\0bad".to_string()]))
            .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("argument 0 must not contain NUL bytes"));

        let error = match runner
            .run(LinuxRouteCommand::new(
                "ip",
                std::iter::repeat_n("route", MAX_LINUX_ROUTE_COMMAND_ARGS + 1),
            ))
            .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("too many arguments"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_route_command_runner_rejects_untrusted_absolute_program_path(
    ) -> Result<(), RouteManagerError> {
        use std::os::unix::fs::PermissionsExt;

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "ipars-route-untrusted-command-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&temp_dir)?;
        std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o777))?;
        let program = temp_dir.join("fake-ip");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n")?;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))?;

        let runner = TimedSystemRouteCommandRunner::new(Duration::from_secs(1));
        let error = match runner
            .run(LinuxRouteCommand::new(
                program.to_string_lossy().to_string(),
                std::iter::empty::<&str>(),
            ))
            .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("must not be group- or world-writable"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_route_command_runner_rejects_symlinked_absolute_program_path(
    ) -> Result<(), RouteManagerError> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "ipars-route-symlinked-command-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&temp_dir)?;
        std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700))?;
        let program = temp_dir.join("linked-shell");
        symlink(trusted_route_test_shell(), &program)?;

        let runner = TimedSystemRouteCommandRunner::new(Duration::from_secs(1));
        let error = match runner
            .run(LinuxRouteCommand::new(
                program.to_string_lossy().to_string(),
                ["-c", "exit 0"],
            ))
            .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("must not be a symlink"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_route_command_runner_rejects_invalid_runtime_bounds() {
        let shell = trusted_route_test_shell();
        let error = match TimedSystemRouteCommandRunner::new(Duration::ZERO)
            .run(LinuxRouteCommand::new(shell.clone(), ["-c", "exit 0"]))
            .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("timeout must be greater than zero"));

        let error = match TimedSystemRouteCommandRunner::new(
            MAX_SYSTEM_ROUTE_COMMAND_TIMEOUT + Duration::from_secs(1),
        )
        .run(LinuxRouteCommand::new(shell.clone(), ["-c", "exit 0"]))
        .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("timeout must not exceed 3600s"));

        let error =
            match TimedSystemRouteCommandRunner::with_output_max_bytes(Duration::from_secs(1), 0)
                .run(LinuxRouteCommand::new(shell.clone(), ["-c", "exit 0"]))
                .await
            {
                Ok(()) => panic!("command should be rejected"),
                Err(error) => error,
            };
        assert!(error
            .to_string()
            .contains("output_max_bytes must be greater than zero"));

        let error = match TimedSystemRouteCommandRunner::with_output_max_bytes(
            Duration::from_secs(1),
            MAX_SYSTEM_ROUTE_COMMAND_OUTPUT_MAX_BYTES + 1,
        )
        .run(LinuxRouteCommand::new(shell, ["-c", "exit 0"]))
        .await
        {
            Ok(()) => panic!("command should be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("output_max_bytes must not exceed 1048576"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_route_command_runner_times_out() {
        let runner = TimedSystemRouteCommandRunner::new(Duration::from_millis(10));
        let shell = trusted_route_test_shell();
        let error = match runner
            .run(LinuxRouteCommand::new(shell, ["-c", "sleep 1"]))
            .await
        {
            Ok(()) => panic!("command should time out"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("timed out after 10ms"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timed_system_route_command_runner_times_out_and_reaps_child(
    ) -> Result<(), RouteManagerError> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "ipars-route-command-timeout-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&temp_dir)?;
        let pid_path = temp_dir.join("child.pid");
        let grandchild_pid_path = temp_dir.join("grandchild.pid");
        let script = format!(
            "printf '%s\\n' $$ > {}; sleep 60 & printf '%s\\n' $! > {}; wait",
            pid_path.display(),
            grandchild_pid_path.display()
        );
        let runner = TimedSystemRouteCommandRunner::new(Duration::from_millis(100));
        let shell = trusted_route_test_shell();
        let error = match runner
            .run(LinuxRouteCommand::new(shell, ["-c", &script]))
            .await
        {
            Ok(()) => panic!("command should time out"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("timed out after 100ms"));
        let pid = wait_for_route_command_pid_file(&pid_path, Duration::from_secs(1)).await?;
        let grandchild_pid =
            wait_for_route_command_pid_file(&grandchild_pid_path, Duration::from_secs(1)).await?;
        assert!(
            wait_for_process_absent(pid, Duration::from_secs(2)).await,
            "timed-out route command child process {pid} was left running"
        );
        assert!(
            wait_for_process_absent(grandchild_pid, Duration::from_secs(2)).await,
            "timed-out route command grandchild process {grandchild_pid} was left running"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_system_route_command_runner_truncates_failure_stderr() {
        let runner =
            TimedSystemRouteCommandRunner::with_output_max_bytes(Duration::from_secs(1), 16);
        let shell = trusted_route_test_shell();
        let error = match runner
            .run(LinuxRouteCommand::new(
                shell,
                ["-c", "printf '0123456789abcdefEXTRA' >&2; exit 7"],
            ))
            .await
        {
            Ok(()) => panic!("command should fail"),
            Err(error) => error,
        };
        let message = error.to_string();
        let stderr = match message.rsplit_once("failed: ") {
            Some((_, stderr)) => stderr,
            None => panic!("failure should include stderr"),
        };

        assert!(stderr.contains("0123456789abcdef"));
        assert!(!stderr.contains("EXTRA"));
        assert!(stderr.contains("stderr truncated after 16 bytes"));
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_route_command_pid_file(
        path: &std::path::Path,
        timeout: Duration,
    ) -> Result<u32, RouteManagerError> {
        let started = std::time::Instant::now();
        loop {
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    let contents = contents.trim();
                    if !contents.is_empty() {
                        return contents.parse::<u32>().map_err(|error| {
                            RouteManagerError::Backend(format!(
                                "failed to parse route command child pid: {error}"
                            ))
                        });
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(RouteManagerError::Io(error)),
            }
            if started.elapsed() >= timeout {
                return Err(RouteManagerError::Backend(format!(
                    "timed out waiting for route command child pid file {}",
                    path.display()
                )));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_process_absent(pid: u32, timeout: Duration) -> bool {
        let started = std::time::Instant::now();
        let process_path = std::path::Path::new("/proc").join(pid.to_string());
        while started.elapsed() < timeout {
            if !process_path.exists() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        !process_path.exists()
    }

    fn route_plan() -> Result<RoutePlan, Box<dyn std::error::Error>> {
        Ok(RoutePlan {
            interface: "ipars0".to_string(),
            routes: vec![Route {
                id: "route-a".to_string(),
                cidr: "10.42.0.0/16".parse()?,
                advertised_by: NodeId::from_string("peer-a"),
                via: None,
                metric: 100,
                tags: Default::default(),
            }],
            policy_rules: vec![PolicyRule {
                table: 10_064,
                priority: 10_064,
                from: Some("10.0.0.0/8".parse()?),
                to: None,
                fwmark: Some(0x6473),
            }],
        })
    }

    #[tokio::test]
    async fn route_plan_validation_rejects_unsafe_and_noncanonical_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = DryRunLinuxRouteManager;
        let cases = [
            ("", "linux interface name cannot be empty", "10.42.0.0/16"),
            (".", "must not be '.' or '..'", "10.42.0.0/16"),
            ("-ipars0", "must not start with '-'", "10.42.0.0/16"),
            (
                "bad interface",
                "must contain only ASCII letters",
                "10.42.0.0/16",
            ),
            ("ipars0", "unrestricted CIDR 0.0.0.0/0", "0.0.0.0/0"),
            ("ipars0", "loopback CIDR 127.0.0.0/8", "127.0.0.0/8"),
            ("ipars0", "canonical CIDR 10.42.0.0/16", "10.42.0.1/16"),
        ];

        for (interface, expected, cidr) in cases {
            let mut plan = route_plan()?;
            plan.interface = interface.to_string();
            plan.routes[0].cidr = cidr.parse()?;
            let error = match manager.apply_routes(plan).await {
                Ok(()) => return Err("invalid route plan should be rejected".into()),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "expected {expected}, got {error}"
            );
        }

        let mut duplicate = route_plan()?;
        duplicate.routes.push(Route {
            id: "route-b".to_string(),
            ..duplicate.routes[0].clone()
        });
        let error = match manager.apply_routes(duplicate).await {
            Ok(()) => return Err("duplicate route plan should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("must not repeat CIDR"));

        let route_id_cases = [
            ("", "route ID cannot be empty"),
            (".", "route ID must not be '.' or '..'"),
            ("..", "route ID must not be '.' or '..'"),
            ("bad/route", "route ID must contain only ASCII letters"),
            ("bad\nroute", "route ID must contain only ASCII letters"),
        ];
        for (route_id, expected) in route_id_cases {
            let mut invalid_id = route_plan()?;
            invalid_id.routes[0].id = route_id.to_string();
            let error = match manager.apply_routes(invalid_id).await {
                Ok(()) => return Err("invalid route ID should be rejected".into()),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains(expected),
                "expected {expected}, got {error}"
            );
        }

        let mut oversized_id = route_plan()?;
        oversized_id.routes[0].id = "a".repeat(129);
        let error = match manager.apply_routes(oversized_id).await {
            Ok(()) => return Err("oversized route ID should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("route ID exceeds 128 bytes"));

        let mut duplicate_route_id = route_plan()?;
        duplicate_route_id.routes.push(Route {
            id: "route-a".to_string(),
            cidr: "10.43.0.0/16".parse()?,
            advertised_by: NodeId::from_string("peer-b"),
            via: None,
            metric: 100,
            tags: Default::default(),
        });
        let error = match manager.apply_routes(duplicate_route_id).await {
            Ok(()) => return Err("duplicate route ID should be rejected".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            RouteManagerError::InvalidRoutePlan(ref message)
                if message.contains("must not repeat route ID route-a")
        ));

        let mut zero_metric = route_plan()?;
        zero_metric.routes[0].metric = 0;
        let error = match manager.apply_routes(zero_metric).await {
            Ok(()) => return Err("zero metric route should be rejected".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            RouteManagerError::InvalidRoutePlan(ref message)
                if message.contains("route route-a metric must be greater than zero")
        ));

        let selector_cases = [
            (
                "from",
                "0.0.0.0/0",
                "from selector must not include unrestricted CIDR 0.0.0.0/0",
            ),
            (
                "from",
                "127.0.0.0/8",
                "from selector must not include loopback CIDR 127.0.0.0/8",
            ),
            (
                "from",
                "10.0.0.1/8",
                "from selector must use canonical CIDR 10.0.0.0/8",
            ),
            (
                "to",
                "169.254.0.0/16",
                "to selector must not include link-local CIDR 169.254.0.0/16",
            ),
            (
                "to",
                "10.42.0.1/16",
                "to selector must use canonical CIDR 10.42.0.0/16",
            ),
        ];
        for (selector, cidr, expected) in selector_cases {
            let mut invalid_selector = route_plan()?;
            match selector {
                "from" => invalid_selector.policy_rules[0].from = Some(cidr.parse()?),
                "to" => invalid_selector.policy_rules[0].to = Some(cidr.parse()?),
                _ => unreachable!(),
            }
            let error = match manager.apply_routes(invalid_selector).await {
                Ok(()) => return Err("invalid policy selector should be rejected".into()),
                Err(error) => error,
            };
            assert!(
                matches!(
                    error,
                    RouteManagerError::InvalidPolicyRule(ref message)
                        if message.contains(expected)
                ),
                "expected {expected}, got {error}"
            );
        }

        let mut duplicate_rule = route_plan()?;
        duplicate_rule
            .policy_rules
            .push(duplicate_rule.policy_rules[0].clone());
        let error = match manager.apply_routes(duplicate_rule).await {
            Ok(()) => return Err("duplicate policy rule should be rejected".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            RouteManagerError::InvalidRoutePlan(ref message)
                if message.contains("must not repeat policy rule priority 10064 for table 10064")
        ));

        let mut duplicate_priority = route_plan()?;
        duplicate_priority.policy_rules.push(PolicyRule {
            table: 10_065,
            priority: 10_064,
            from: Some("10.1.0.0/16".parse()?),
            to: None,
            fwmark: Some(0x6474),
        });
        let error = match manager.apply_routes(duplicate_priority).await {
            Ok(()) => return Err("duplicate policy rule priority should be rejected".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            RouteManagerError::InvalidRoutePlan(ref message)
                if message.contains("must not reuse policy rule priority 10064")
        ));

        let mut zero_fwmark = route_plan()?;
        zero_fwmark.policy_rules[0].fwmark = Some(0);
        let error = match manager.apply_routes(zero_fwmark).await {
            Ok(()) => return Err("zero fwmark policy rule should be rejected".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            RouteManagerError::InvalidPolicyRule(ref message)
                if message.contains("fwmark selector must be nonzero when set")
        ));

        let mut invalid_rule = route_plan()?;
        invalid_rule.policy_rules[0].table = 0;
        let error = match manager.apply_routes(invalid_rule).await {
            Ok(()) => return Err("invalid policy rule should be rejected".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            RouteManagerError::InvalidPolicyRule(ref message)
                if message.contains("must use a nonzero routing table")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn linux_route_manager_validates_plan_before_running_commands(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let manager = LinuxRouteManager::new(runner.clone());
        let mut plan = route_plan()?;
        plan.routes[0].cidr = "10.42.0.1/16".parse()?;

        let error = match manager.apply_routes(plan).await {
            Ok(()) => return Err("invalid route plan should be rejected".into()),
            Err(error) => error,
        };

        assert!(matches!(error, RouteManagerError::InvalidRoutePlan(_)));
        assert!(runner.commands().await.is_empty());
        Ok(())
    }

    #[test]
    fn linux_network_namespace_validates_name() -> Result<(), Box<dyn std::error::Error>> {
        let namespace = LinuxNetworkNamespace::from_name("node-a_1.prod")?;

        assert_eq!(namespace.name(), "node-a_1.prod");
        assert_eq!(
            namespace.path(),
            PathBuf::from("/var/run/netns/node-a_1.prod")
        );
        assert!(matches!(
            LinuxNetworkNamespace::from_name(""),
            Err(RouteManagerError::InvalidNamespace(name)) if name.is_empty()
        ));
        assert!(matches!(
            LinuxNetworkNamespace::from_name("../node-a"),
            Err(RouteManagerError::InvalidNamespace(name)) if name == "../node-a"
        ));
        assert!(matches!(
            LinuxNetworkNamespace::from_name("node a"),
            Err(RouteManagerError::InvalidNamespace(name)) if name == "node a"
        ));
        assert!(matches!(
            LinuxNetworkNamespace::from_name("."),
            Err(RouteManagerError::InvalidNamespace(name)) if name == "."
        ));
        assert!(matches!(
            LinuxNetworkNamespace::from_name(".."),
            Err(RouteManagerError::InvalidNamespace(name)) if name == ".."
        ));
        assert!(matches!(
            LinuxNetworkNamespace::from_name("-node-a"),
            Err(RouteManagerError::InvalidNamespace(name)) if name == "-node-a"
        ));
        Ok(())
    }

    #[test]
    fn linux_network_namespace_path_inspection_rejects_missing_and_directory(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let base = route_manager_test_dir("netns-path")?;
        let missing = base.join("missing");
        let error = match inspect_linux_netns_path(&namespace, &missing) {
            Ok(()) => return Err("missing namespace path should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("does not exist"));

        let directory = base.join("directory");
        std::fs::create_dir(&directory)?;
        let error = match inspect_linux_netns_path(&namespace, &directory) {
            Ok(()) => return Err("namespace directory path should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("not a directory"));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_network_namespace_path_inspection_rejects_regular_file(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let base = route_manager_test_dir("netns-path-regular")?;
        let path = base.join("node-a");
        std::fs::write(&path, b"netns")?;

        let error = match inspect_linux_netns_path(&namespace, &path) {
            Ok(()) => return Err("regular namespace path should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("nsfs namespace bind mount"));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn linux_network_namespace_path_inspection_rejects_symlink(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let base = route_manager_test_dir("netns-path-symlink")?;
        let target = base.join("target");
        let link = base.join("node-a");
        std::fs::write(&target, b"netns")?;
        std::os::unix::fs::symlink(&target, &link)?;

        let error = match inspect_linux_netns_path(&namespace, &link) {
            Ok(()) => return Err("symlink namespace path should be rejected".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("must not be a symlink"));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn netns_identity_detects_same_file() -> Result<(), Box<dyn std::error::Error>> {
        let base = route_manager_test_dir("netns-path-identity")?;
        let target = base.join("target");
        let current = base.join("current");
        let other = base.join("other");
        std::fs::write(&target, b"netns")?;
        std::fs::hard_link(&target, &current)?;
        std::fs::write(&other, b"other-netns")?;

        let target_metadata = std::fs::metadata(&target)?;
        let current_metadata = std::fs::metadata(&current)?;
        let other_metadata = std::fs::metadata(&other)?;
        assert!(same_file_metadata_identity(
            &target_metadata,
            &current_metadata
        ));
        assert!(!same_file_metadata_identity(
            &target_metadata,
            &other_metadata
        ));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn netns_current_match_treats_distinct_file_as_other_namespace(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let base = route_manager_test_dir("netns-path-current-match")?;
        let path = base.join("node-a");
        std::fs::write(&path, b"netns")?;

        assert!(!linux_netns_path_matches_current(&path)?);
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    fn route_manager_test_dir(prefix: &str) -> io::Result<PathBuf> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ipars-route-manager-{prefix}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&path)?;
        Ok(path)
    }

    #[test]
    fn netlink_namespace_context_restores_after_error_and_nested_scope(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let outer = LinuxNetworkNamespace::from_name("outer-ns")?;
        let inner = LinuxNetworkNamespace::from_name("inner-ns")?;

        let error = match with_netlink_namespace(Some(&outer), || {
            assert_eq!(
                current_test_netlink_namespace_name().as_deref(),
                Some("outer-ns")
            );
            let nested: io::Result<()> = with_netlink_namespace(Some(&inner), || {
                assert_eq!(
                    current_test_netlink_namespace_name().as_deref(),
                    Some("inner-ns")
                );
                Err(io::Error::other("nested failure"))
            });
            assert_eq!(
                current_test_netlink_namespace_name().as_deref(),
                Some("outer-ns")
            );
            nested
        }) {
            Ok(()) => return Err("nested namespace operation should fail".into()),
            Err(error) => error,
        };

        assert_eq!(error.to_string(), "nested failure");
        assert_eq!(current_test_netlink_namespace_name(), None);
        Ok(())
    }

    #[test]
    fn netlink_namespace_context_restores_after_panic() -> Result<(), Box<dyn std::error::Error>> {
        let namespace = LinuxNetworkNamespace::from_name("panic-ns")?;

        let result = std::panic::catch_unwind(|| {
            let _ = with_netlink_namespace(Some(&namespace), || -> io::Result<()> {
                assert_eq!(
                    current_test_netlink_namespace_name().as_deref(),
                    Some("panic-ns")
                );
                panic!("forced namespace panic");
            });
        });

        assert!(result.is_err());
        assert_eq!(current_test_netlink_namespace_name(), None);
        Ok(())
    }

    fn current_test_netlink_namespace_name() -> Option<String> {
        NETLINK_NAMESPACE.with(|namespace| {
            namespace
                .borrow()
                .as_ref()
                .map(|namespace| namespace.name().to_string())
        })
    }

    #[test]
    fn linux_netlink_route_manager_tracks_namespace() -> Result<(), Box<dyn std::error::Error>> {
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let manager = LinuxNetlinkRouteManager::new_in_namespace(namespace.clone());

        assert_eq!(manager.namespace(), Some(&namespace));
        assert_eq!(LinuxNetlinkRouteManager::new().namespace(), None);
        Ok(())
    }

    #[tokio::test]
    async fn namespaced_route_runner_wraps_command() -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let namespace = LinuxNetworkNamespace::from_name("node-a")?;
        let namespaced_runner = NamespacedLinuxRouteCommandRunner::new(namespace, runner.clone());

        namespaced_runner
            .run(LinuxRouteCommand::new("ip", ["route", "show"]))
            .await?;

        assert_eq!(
            runner.commands().await,
            vec![LinuxRouteCommand::new(
                "ip",
                ["netns", "exec", "node-a", "ip", "route", "show"],
            )]
        );
        Ok(())
    }

    #[tokio::test]
    async fn docker_intent_builds_explicit_route_plan() -> Result<(), Box<dyn std::error::Error>> {
        let manager = DryRunLinuxRouteManager;
        let plan = manager
            .apply_docker_intent(DockerNetworkIntent {
                container_namespace: "container-a".to_string(),
                host_interface: "eth0".to_string(),
                overlay_interface: "ipars0".to_string(),
                container_cidrs: vec!["172.18.0.0/16".parse()?],
                expose_host_routes: true,
            })
            .await?;

        assert_eq!(plan.interface, "ipars0");
        assert_eq!(plan.routes.len(), 1);
        assert_eq!(plan.policy_rules[0].table, 10_064);
        Ok(())
    }

    #[tokio::test]
    async fn docker_intent_rejects_invalid_container_cidrs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = DryRunLinuxRouteManager;
        let cases = [
            (vec!["0.0.0.0/0"], "unrestricted Docker container CIDR"),
            (vec!["127.0.0.0/8"], "loopback Docker container CIDR"),
            (
                vec!["172.18.0.1/16"],
                "canonical Docker container CIDR route 172.18.0.0/16",
            ),
            (
                vec!["172.18.0.0/16", "172.18.0.0/16"],
                "repeat Docker container CIDR route 172.18.0.0/16",
            ),
            (
                vec!["172.18.0.0/16", "172.18.10.0/24"],
                "overlapping Docker container CIDR routes 172.18.0.0/16 and 172.18.10.0/24",
            ),
        ];

        for (cidrs, expected) in cases {
            let error = match manager
                .apply_docker_intent(DockerNetworkIntent {
                    container_namespace: "container-a".to_string(),
                    host_interface: "eth0".to_string(),
                    overlay_interface: "ipars0".to_string(),
                    container_cidrs: cidrs
                        .into_iter()
                        .map(str::parse)
                        .collect::<Result<Vec<IpNet>, _>>()?,
                    expose_host_routes: true,
                })
                .await
            {
                Ok(plan) => {
                    return Err(format!("invalid Docker CIDR should be rejected: {plan:?}").into());
                }
                Err(error) => error,
            };

            assert!(
                matches!(error, RouteManagerError::InvalidDockerNetworkIntent(ref message) if message.contains(expected)),
                "unexpected error: {error}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn docker_intent_rejects_invalid_container_namespace(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = DryRunLinuxRouteManager;
        let cases = [
            "".to_string(),
            ".".to_string(),
            "..".to_string(),
            "-container-a".to_string(),
            "container/a".to_string(),
            "a".repeat(65),
        ];

        for container_namespace in cases {
            let error = match manager
                .apply_docker_intent(DockerNetworkIntent {
                    container_namespace,
                    host_interface: "eth0".to_string(),
                    overlay_interface: "ipars0".to_string(),
                    container_cidrs: vec!["172.18.0.0/16".parse()?],
                    expose_host_routes: true,
                })
                .await
            {
                Ok(plan) => {
                    return Err(
                        format!("invalid Docker namespace should be rejected: {plan:?}").into(),
                    );
                }
                Err(error) => error,
            };

            assert!(
                matches!(
                    error,
                    RouteManagerError::InvalidDockerNetworkIntent(ref message)
                        if message.contains("valid linux network namespace name")
                ),
                "unexpected error: {error}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn kubernetes_intent_builds_service_and_api_routes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = DryRunLinuxRouteManager;
        let plan = manager
            .apply_kubernetes_intent(KubernetesUnderlayIntent {
                node_name: "worker-a".to_string(),
                overlay_interface: "ipars0".to_string(),
                api_server_cidrs: vec!["10.0.0.1/32".parse()?],
                service_cidrs: vec!["10.96.0.0/12".parse()?],
                route_provider: NodeId::from_string("route-provider-a"),
            })
            .await?;

        assert_eq!(plan.interface, "ipars0");
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.routes[0].id, "k8s-v4-10-0-0-1-32");
        assert_eq!(plan.routes[0].cidr, "10.0.0.1/32".parse::<IpNet>()?);
        assert_eq!(
            plan.routes[0].via,
            Some(NodeId::from_string("route-provider-a"))
        );
        assert_eq!(plan.routes[1].id, "k8s-v4-10-96-0-0-12");
        assert_eq!(plan.routes[1].cidr, "10.96.0.0/12".parse::<IpNet>()?);
        assert_eq!(plan.policy_rules[0].priority, 10_050);
        Ok(())
    }

    #[test]
    fn kubernetes_route_plan_uses_stable_cidr_derived_ids() -> Result<(), Box<dyn std::error::Error>>
    {
        let plan = kubernetes_route_plan(KubernetesUnderlayIntent {
            node_name: "worker-a".to_string(),
            overlay_interface: "ipars0".to_string(),
            api_server_cidrs: vec!["fd00:96::1/128".parse()?, "10.0.0.1/32".parse()?],
            service_cidrs: vec!["10.96.0.0/12".parse()?],
            route_provider: NodeId::from_string("route-provider-a"),
        });

        assert_eq!(
            plan.routes
                .iter()
                .map(|route| route.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "k8s-v4-10-0-0-1-32",
                "k8s-v4-10-96-0-0-12",
                "k8s-v6-fd00-96-0-0-0-0-0-1-128",
            ]
        );
        assert_eq!(plan.routes[0].cidr, "10.0.0.1/32".parse::<IpNet>()?);
        assert_eq!(plan.routes[1].cidr, "10.96.0.0/12".parse::<IpNet>()?);
        assert_eq!(plan.routes[2].cidr, "fd00:96::1/128".parse::<IpNet>()?);
        assert!(plan.routes.iter().all(|route| {
            route.advertised_by == NodeId::from_string("route-provider-a")
                && route.via == Some(NodeId::from_string("route-provider-a"))
        }));
        Ok(())
    }

    #[tokio::test]
    async fn kubernetes_intent_allows_specific_route_inside_service_cidr(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = DryRunLinuxRouteManager;
        let plan = manager
            .apply_kubernetes_intent(KubernetesUnderlayIntent {
                node_name: "worker-a".to_string(),
                overlay_interface: "ipars0".to_string(),
                api_server_cidrs: vec!["10.96.0.1/32".parse()?],
                service_cidrs: vec!["10.96.0.0/12".parse()?],
                route_provider: NodeId::from_string("route-provider-a"),
            })
            .await?;

        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.routes[0].id, "k8s-v4-10-96-0-0-12");
        assert_eq!(plan.routes[0].cidr, "10.96.0.0/12".parse::<IpNet>()?);
        assert_eq!(plan.routes[1].id, "k8s-v4-10-96-0-1-32");
        assert_eq!(plan.routes[1].cidr, "10.96.0.1/32".parse::<IpNet>()?);
        Ok(())
    }

    #[tokio::test]
    async fn kubernetes_intent_rejects_invalid_route_cidrs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = DryRunLinuxRouteManager;
        let cases = [
            (
                vec!["0.0.0.0/0"],
                Vec::new(),
                "unrestricted Kubernetes API server CIDR",
            ),
            (
                Vec::new(),
                vec!["127.0.0.0/8"],
                "loopback Kubernetes Service CIDR",
            ),
            (
                Vec::new(),
                vec!["10.96.0.1/12"],
                "canonical Kubernetes Service CIDR route 10.96.0.0/12",
            ),
            (
                vec!["10.96.0.1/32"],
                vec!["10.96.0.1/32"],
                "repeat Kubernetes underlay route CIDR 10.96.0.1/32",
            ),
        ];

        for (api_server_cidrs, service_cidrs, expected) in cases {
            let error = match manager
                .apply_kubernetes_intent(KubernetesUnderlayIntent {
                    node_name: "worker-a".to_string(),
                    overlay_interface: "ipars0".to_string(),
                    api_server_cidrs: api_server_cidrs
                        .into_iter()
                        .map(str::parse)
                        .collect::<Result<Vec<_>, _>>()?,
                    service_cidrs: service_cidrs
                        .into_iter()
                        .map(str::parse)
                        .collect::<Result<Vec<_>, _>>()?,
                    route_provider: NodeId::from_string("route-provider-a"),
                })
                .await
            {
                Ok(plan) => {
                    return Err(
                        format!("invalid Kubernetes CIDR should be rejected: {plan:?}").into(),
                    );
                }
                Err(error) => error,
            };

            assert!(
                matches!(error, RouteManagerError::InvalidKubernetesUnderlayIntent(ref message) if message.contains(expected)),
                "unexpected error: {error}"
            );
        }
        Ok(())
    }

    #[test]
    fn linux_netlink_route_message_sets_destination_interface_table_and_metric(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let route = Route {
            id: "route-a".to_string(),
            cidr: "10.42.0.0/16".parse()?,
            advertised_by: NodeId::from_string("peer-a"),
            via: None,
            metric: 100,
            tags: Default::default(),
        };

        let message = netlink_route_message(&route, 7, Some(10_064));

        assert_eq!(message.header.address_family, AddressFamily::Inet);
        assert_eq!(message.header.destination_prefix_length, 16);
        assert!(message
            .attributes
            .contains(&RouteAttribute::Destination(RouteAddress::Inet(
                "10.42.0.0".parse()?
            ))));
        assert!(message.attributes.contains(&RouteAttribute::Oif(7)));
        assert!(message.attributes.contains(&RouteAttribute::Table(10_064)));
        assert!(message.attributes.contains(&RouteAttribute::Priority(100)));
        Ok(())
    }

    #[test]
    fn linux_netlink_rule_message_sets_selectors_mark_and_table(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rule = PolicyRule {
            table: 10_064,
            priority: 10_050,
            from: Some("10.0.0.0/8".parse()?),
            to: Some("10.42.0.0/16".parse()?),
            fwmark: Some(0x6473),
        };

        let message = netlink_rule_message(&rule)?;

        assert_eq!(message.header.family, AddressFamily::Inet);
        assert_eq!(message.header.action, RuleAction::ToTable);
        assert_eq!(message.header.src_len, 8);
        assert_eq!(message.header.dst_len, 16);
        assert!(message
            .attributes
            .contains(&RuleAttribute::Priority(10_050)));
        assert!(message.attributes.contains(&RuleAttribute::Table(10_064)));
        assert!(message.attributes.contains(&RuleAttribute::FwMark(0x6473)));
        assert!(message
            .attributes
            .contains(&RuleAttribute::Source("10.0.0.0".parse()?)));
        assert!(message
            .attributes
            .contains(&RuleAttribute::Destination("10.42.0.0".parse()?)));
        Ok(())
    }

    #[test]
    fn linux_netlink_rule_message_rejects_mixed_ip_families(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rule = PolicyRule {
            table: 10_064,
            priority: 10_050,
            from: Some("10.0.0.0/8".parse()?),
            to: Some("fd00::/64".parse()?),
            fwmark: None,
        };

        assert!(matches!(
            netlink_rule_message(&rule),
            Err(RouteManagerError::InvalidPolicyRule(message))
                if message.contains("mixes IPv4 and IPv6")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn linux_route_manager_generates_apply_and_remove_commands(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let manager = LinuxRouteManager::new(runner.clone());
        let plan = route_plan()?;

        manager.apply_routes(plan.clone()).await?;
        manager.remove_routes(plan).await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "route",
                        "replace",
                        "10.42.0.0/16",
                        "dev",
                        "ipars0",
                        "table",
                        "10064",
                        "metric",
                        "100",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "rule",
                        "del",
                        "priority",
                        "10064",
                        "from",
                        "10.0.0.0/8",
                        "fwmark",
                        "0x6473",
                        "table",
                        "10064",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "rule",
                        "add",
                        "priority",
                        "10064",
                        "from",
                        "10.0.0.0/8",
                        "fwmark",
                        "0x6473",
                        "table",
                        "10064",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "rule",
                        "del",
                        "priority",
                        "10064",
                        "from",
                        "10.0.0.0/8",
                        "fwmark",
                        "0x6473",
                        "table",
                        "10064",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "route",
                        "del",
                        "10.42.0.0/16",
                        "dev",
                        "ipars0",
                        "table",
                        "10064",
                    ],
                ),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_route_manager_ignores_missing_rule_during_apply(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::with_failed_rule_delete();
        let manager = LinuxRouteManager::new(runner.clone());

        manager.apply_routes(route_plan()?).await?;

        assert_eq!(
            runner.commands().await,
            vec![
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "route",
                        "replace",
                        "10.42.0.0/16",
                        "dev",
                        "ipars0",
                        "table",
                        "10064",
                        "metric",
                        "100",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "rule",
                        "del",
                        "priority",
                        "10064",
                        "from",
                        "10.0.0.0/8",
                        "fwmark",
                        "0x6473",
                        "table",
                        "10064",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "rule",
                        "add",
                        "priority",
                        "10064",
                        "from",
                        "10.0.0.0/8",
                        "fwmark",
                        "0x6473",
                        "table",
                        "10064",
                    ],
                ),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_route_manager_applies_docker_intent_plan(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let manager = LinuxRouteManager::new(runner.clone());

        let plan = manager
            .apply_docker_intent(DockerNetworkIntent {
                container_namespace: "container-a".to_string(),
                host_interface: "eth0".to_string(),
                overlay_interface: "ipars0".to_string(),
                container_cidrs: vec!["172.18.0.0/16".parse()?],
                expose_host_routes: true,
            })
            .await?;

        assert_eq!(plan.routes[0].cidr, "172.18.0.0/16".parse::<IpNet>()?);
        assert_eq!(
            runner.commands().await,
            vec![
                LinuxRouteCommand::new(
                    "ip",
                    [
                        "route",
                        "replace",
                        "172.18.0.0/16",
                        "dev",
                        "ipars0",
                        "table",
                        "10064",
                        "metric",
                        "100",
                    ],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    ["rule", "del", "priority", "10064", "fwmark", "0x6473", "table", "10064",],
                ),
                LinuxRouteCommand::new(
                    "ip",
                    ["rule", "add", "priority", "10064", "fwmark", "0x6473", "table", "10064",],
                ),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn linux_route_manager_rejects_invalid_docker_intent_before_commands(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let manager = LinuxRouteManager::new(runner.clone());

        let error = match manager
            .apply_docker_intent(DockerNetworkIntent {
                container_namespace: "container-a".to_string(),
                host_interface: "eth0".to_string(),
                overlay_interface: "ipars0".to_string(),
                container_cidrs: vec!["172.18.0.1/16".parse()?],
                expose_host_routes: true,
            })
            .await
        {
            Ok(plan) => {
                return Err(format!(
                    "invalid Docker intent should fail before route commands: {plan:?}"
                )
                .into());
            }
            Err(error) => error,
        };

        assert!(
            matches!(
                error,
                RouteManagerError::InvalidDockerNetworkIntent(ref message)
                    if message.contains("canonical Docker container CIDR route 172.18.0.0/16")
            ),
            "unexpected error: {error}"
        );
        assert!(runner.commands().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn linux_route_manager_rejects_invalid_docker_namespace_before_commands(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let manager = LinuxRouteManager::new(runner.clone());

        let error = match manager
            .apply_docker_intent(DockerNetworkIntent {
                container_namespace: "../container-a".to_string(),
                host_interface: "eth0".to_string(),
                overlay_interface: "ipars0".to_string(),
                container_cidrs: vec!["172.18.0.0/16".parse()?],
                expose_host_routes: true,
            })
            .await
        {
            Ok(plan) => {
                return Err(format!(
                    "invalid Docker namespace should fail before route commands: {plan:?}"
                )
                .into());
            }
            Err(error) => error,
        };

        assert!(
            matches!(
                error,
                RouteManagerError::InvalidDockerNetworkIntent(ref message)
                    if message.contains("valid linux network namespace name")
            ),
            "unexpected error: {error}"
        );
        assert!(runner.commands().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn linux_route_manager_rejects_invalid_kubernetes_intent_before_commands(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = RecordingRunner::default();
        let manager = LinuxRouteManager::new(runner.clone());

        let error = match manager
            .apply_kubernetes_intent(KubernetesUnderlayIntent {
                node_name: "worker-a".to_string(),
                overlay_interface: "ipars0".to_string(),
                api_server_cidrs: Vec::new(),
                service_cidrs: vec!["10.96.0.1/12".parse()?],
                route_provider: NodeId::from_string("route-provider-a"),
            })
            .await
        {
            Ok(plan) => {
                return Err(format!(
                    "invalid Kubernetes intent should fail before route commands: {plan:?}"
                )
                .into());
            }
            Err(error) => error,
        };

        assert!(
            matches!(
                error,
                RouteManagerError::InvalidKubernetesUnderlayIntent(ref message)
                    if message.contains("canonical Kubernetes Service CIDR route 10.96.0.0/12")
            ),
            "unexpected error: {error}"
        );
        assert!(runner.commands().await.is_empty());
        Ok(())
    }
}
