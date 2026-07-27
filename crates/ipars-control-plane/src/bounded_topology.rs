//! Deterministic block-aware bounded-degree topology synthesis for the relay backbone.
//!
//! The topology is the union of Hamiltonian cycles whose members remain
//! contiguous inside deterministic blocks. The first cycle follows stable
//! block and node-ID order and guarantees connectedness. Additional cycles use
//! domain-separated SHA-256 block and member orderings, which provide redundant
//! representatives and lower diameter without allowing any cycle to add more
//! than two neighbors per node.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ipars_crypto::node_id_from_public_key;
use ipars_types::{
    NodeId, NodeRecord, DEFAULT_OVERLAY_BLOCK_SIZE, MAX_OVERLAY_BLOCK_SIZE, MIN_OVERLAY_BLOCK_SIZE,
};
use thiserror::Error;

pub const TOPOLOGY_ALGORITHM_VERSION: &str = "block-aware-hamiltonian-cycle-union-v2";
const DEFAULT_PERMUTATION_SEED: &str = "ipars-bounded-backbone";

pub const SUPPORTED_MAX_DEGREES: [usize; 2] = [4, 6];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedTopologyConfig {
    pub max_degree: usize,
    pub block_size: usize,
    /// Stable namespace for independent clusters or topology policies.
    pub permutation_seed: String,
}

impl BoundedTopologyConfig {
    pub fn new(max_degree: usize) -> Self {
        Self {
            max_degree,
            block_size: usize::from(DEFAULT_OVERLAY_BLOCK_SIZE),
            permutation_seed: DEFAULT_PERMUTATION_SEED.to_string(),
        }
    }

    pub fn with_block_size(mut self, block_size: usize) -> Self {
        self.block_size = block_size;
        self
    }

    pub fn with_permutation_seed(mut self, permutation_seed: impl Into<String>) -> Self {
        self.permutation_seed = permutation_seed.into();
        self
    }
}

impl Default for BoundedTopologyConfig {
    fn default() -> Self {
        Self::new(6)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TopologyEdge {
    first: NodeId,
    second: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyBlock {
    block_id: String,
    node_ids: Vec<NodeId>,
}

impl TopologyBlock {
    pub fn block_id(&self) -> &str {
        &self.block_id
    }

    pub fn node_ids(&self) -> &[NodeId] {
        &self.node_ids
    }
}

impl TopologyEdge {
    pub fn new(first: NodeId, second: NodeId) -> Option<Self> {
        if first == second {
            return None;
        }
        if first < second {
            Some(Self { first, second })
        } else {
            Some(Self {
                first: second,
                second: first,
            })
        }
    }

    pub fn first(&self) -> &NodeId {
        &self.first
    }

    pub fn second(&self) -> &NodeId {
        &self.second
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondaryPathKind {
    /// The paths share only their endpoints and do not share an edge.
    VertexDisjoint,
    /// The paths do not share an edge but may share internal vertices.
    EdgeDisjoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondaryPath {
    pub kind: SecondaryPathKind,
    pub nodes: Vec<NodeId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyPaths {
    pub primary: Vec<NodeId>,
    pub secondary: Option<SecondaryPath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyInvariants {
    pub node_count: usize,
    pub edge_count: usize,
    pub max_observed_degree: usize,
    pub connected: bool,
    pub symmetric: bool,
    pub no_self_loops: bool,
    pub within_degree_bound: bool,
}

impl TopologyInvariants {
    pub fn are_satisfied(&self) -> bool {
        self.connected && self.symmetric && self.no_self_loops && self.within_degree_bound
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BoundedTopologyError {
    #[error("unsupported maximum degree {max_degree}; supported maximum degrees are 4 and 6")]
    UnsupportedMaxDegree { max_degree: usize },
    #[error("invalid block size {block_size}; block size must be between {minimum} and {maximum}")]
    InvalidBlockSize {
        block_size: usize,
        minimum: usize,
        maximum: usize,
    },
    #[error("duplicate node ID in bounded topology membership: {node_id}")]
    DuplicateNodeId { node_id: NodeId },
    #[error("bounded topology synthesis violated invariant: {reason}")]
    InvariantViolation { reason: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedTopology {
    topology_epoch: u64,
    max_degree: usize,
    block_size: usize,
    blocks: Vec<TopologyBlock>,
    edge_cycles: BTreeMap<TopologyEdge, BTreeSet<usize>>,
    adjacency: BTreeMap<NodeId, BTreeSet<NodeId>>,
    invariants: TopologyInvariants,
}

impl BoundedTopology {
    pub fn synthesize(
        nodes: &[NodeRecord],
        config: &BoundedTopologyConfig,
    ) -> Result<Self, BoundedTopologyError> {
        if !SUPPORTED_MAX_DEGREES.contains(&config.max_degree) {
            return Err(BoundedTopologyError::UnsupportedMaxDegree {
                max_degree: config.max_degree,
            });
        }
        let minimum_block_size = usize::from(MIN_OVERLAY_BLOCK_SIZE);
        let maximum_block_size = usize::from(MAX_OVERLAY_BLOCK_SIZE);
        if !(minimum_block_size..=maximum_block_size).contains(&config.block_size) {
            return Err(BoundedTopologyError::InvalidBlockSize {
                block_size: config.block_size,
                minimum: minimum_block_size,
                maximum: maximum_block_size,
            });
        }

        let node_ids = canonical_node_ids(nodes)?;
        let topology_epoch = topology_epoch(&node_ids, config);
        let blocks = topology_blocks(&node_ids, config.block_size);
        let mut adjacency = node_ids
            .iter()
            .cloned()
            .map(|node_id| (node_id, BTreeSet::new()))
            .collect::<BTreeMap<_, _>>();
        let mut edge_cycles = BTreeMap::<TopologyEdge, BTreeSet<usize>>::new();

        let cycle_count = config.max_degree / 2;
        for cycle_index in 0..cycle_count {
            let cycle = block_aware_cycle(&blocks, cycle_index, config);
            add_hamiltonian_cycle(&mut adjacency, &mut edge_cycles, &cycle, cycle_index);
        }

        let invariants = inspect_invariants(&adjacency, config.max_degree);
        if !invariants.connected {
            return Err(BoundedTopologyError::InvariantViolation {
                reason: "graph is disconnected",
            });
        }
        if !invariants.symmetric {
            return Err(BoundedTopologyError::InvariantViolation {
                reason: "adjacency is asymmetric",
            });
        }
        if !invariants.no_self_loops {
            return Err(BoundedTopologyError::InvariantViolation {
                reason: "graph contains a self-loop",
            });
        }
        if !invariants.within_degree_bound {
            return Err(BoundedTopologyError::InvariantViolation {
                reason: "graph exceeds the configured maximum degree",
            });
        }

        Ok(Self {
            topology_epoch,
            max_degree: config.max_degree,
            block_size: config.block_size,
            blocks,
            edge_cycles,
            adjacency,
            invariants,
        })
    }

    pub fn topology_epoch(&self) -> u64 {
        self.topology_epoch
    }

    pub fn max_degree(&self) -> usize {
        self.max_degree
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    pub fn blocks(&self) -> &[TopologyBlock] {
        &self.blocks
    }

    pub fn edge_cycles(&self) -> &BTreeMap<TopologyEdge, BTreeSet<usize>> {
        &self.edge_cycles
    }

    pub fn adjacency(&self) -> &BTreeMap<NodeId, BTreeSet<NodeId>> {
        &self.adjacency
    }

    pub fn invariants(&self) -> &TopologyInvariants {
        &self.invariants
    }

    pub fn neighbors(&self, node_id: &NodeId) -> Option<&BTreeSet<NodeId>> {
        self.adjacency.get(node_id)
    }

    pub fn shortest_path(&self, source: &NodeId, destination: &NodeId) -> Option<Vec<NodeId>> {
        self.shortest_path_avoiding(source, destination, &BTreeSet::new(), &BTreeSet::new())
    }

    pub fn shortest_path_avoiding(
        &self,
        source: &NodeId,
        destination: &NodeId,
        unavailable_nodes: &BTreeSet<NodeId>,
        unavailable_edges: &BTreeSet<TopologyEdge>,
    ) -> Option<Vec<NodeId>> {
        if !self.adjacency.contains_key(source)
            || !self.adjacency.contains_key(destination)
            || unavailable_nodes.contains(source)
            || unavailable_nodes.contains(destination)
        {
            return None;
        }
        if source == destination {
            return Some(vec![source.clone()]);
        }

        let mut visited = BTreeSet::from([source.clone()]);
        let mut predecessor = BTreeMap::<NodeId, NodeId>::new();
        let mut queue = VecDeque::from([source.clone()]);

        while let Some(current) = queue.pop_front() {
            let Some(neighbors) = self.adjacency.get(&current) else {
                continue;
            };
            for neighbor in neighbors {
                if unavailable_nodes.contains(neighbor)
                    || edge_is_unavailable(&current, neighbor, unavailable_edges)
                    || !visited.insert(neighbor.clone())
                {
                    continue;
                }
                predecessor.insert(neighbor.clone(), current.clone());
                if neighbor == destination {
                    return reconstruct_path(source, destination, &predecessor);
                }
                queue.push_back(neighbor.clone());
            }
        }
        None
    }

    pub fn paths(&self, source: &NodeId, destination: &NodeId) -> Option<TopologyPaths> {
        let primary = self.shortest_path(source, destination)?;
        if source == destination {
            return Some(TopologyPaths {
                primary,
                secondary: None,
            });
        }

        let secondary = self.secondary_path(source, destination, &primary);

        Some(TopologyPaths { primary, secondary })
    }

    fn secondary_path(
        &self,
        source: &NodeId,
        destination: &NodeId,
        primary: &[NodeId],
    ) -> Option<SecondaryPath> {
        let primary_edges = path_edges(primary);
        let primary_internal_nodes = primary
            .iter()
            .skip(1)
            .take(primary.len().saturating_sub(2))
            .cloned()
            .collect::<BTreeSet<_>>();

        let vertex_disjoint = self.shortest_path_avoiding(
            source,
            destination,
            &primary_internal_nodes,
            &primary_edges,
        );
        if let Some(nodes) = vertex_disjoint {
            Some(SecondaryPath {
                kind: SecondaryPathKind::VertexDisjoint,
                nodes,
            })
        } else {
            self.shortest_path_avoiding(source, destination, &BTreeSet::new(), &primary_edges)
                .map(|nodes| SecondaryPath {
                    kind: SecondaryPathKind::EdgeDisjoint,
                    nodes,
                })
        }
    }

    /// Compute first hops with the same path-disjointness semantics as
    /// [`Self::paths`]. Primary paths share one BFS tree; alternate paths are
    /// resolved per destination to preserve vertex-first, edge-only fallback.
    pub fn next_hops_from(
        &self,
        source: &NodeId,
    ) -> Option<BTreeMap<NodeId, (NodeId, Option<NodeId>)>> {
        self.adjacency.get(source)?;
        let primary_predecessors = predecessor_tree_from(source, &self.adjacency);
        let mut next_hops = BTreeMap::new();
        for destination in self.adjacency.keys().filter(|node| *node != source) {
            let Some(primary) = reconstruct_path(source, destination, &primary_predecessors) else {
                continue;
            };
            let Some(primary_next_hop) = primary.get(1).cloned() else {
                continue;
            };
            let secondary_next_hop = self
                .secondary_path(source, destination, &primary)
                .and_then(|secondary| secondary.nodes.get(1).cloned())
                .filter(|secondary| secondary != &primary_next_hop);
            next_hops.insert(destination.clone(), (primary_next_hop, secondary_next_hop));
        }
        Some(next_hops)
    }

    /// Returns `None` for an empty or disconnected graph.
    pub fn diameter(&self) -> Option<usize> {
        if self.adjacency.is_empty() {
            return None;
        }

        let mut diameter = 0;
        for source in self.adjacency.keys() {
            let distances = distances_from(source, &self.adjacency);
            if distances.len() != self.adjacency.len() {
                return None;
            }
            if let Some(farthest) = distances.values().max() {
                diameter = diameter.max(*farthest);
            }
        }
        Some(diameter)
    }
}

pub fn synthesize_bounded_topology(
    nodes: &[NodeRecord],
    config: &BoundedTopologyConfig,
) -> Result<BoundedTopology, BoundedTopologyError> {
    BoundedTopology::synthesize(nodes, config)
}

fn canonical_node_ids(nodes: &[NodeRecord]) -> Result<Vec<NodeId>, BoundedTopologyError> {
    let mut node_ids = nodes
        .iter()
        .map(|node| node.node_id.clone())
        .collect::<Vec<_>>();
    node_ids.sort();

    for adjacent in node_ids.windows(2) {
        if adjacent[0] == adjacent[1] {
            return Err(BoundedTopologyError::DuplicateNodeId {
                node_id: adjacent[0].clone(),
            });
        }
    }
    Ok(node_ids)
}

fn topology_blocks(node_ids: &[NodeId], block_size: usize) -> Vec<TopologyBlock> {
    node_ids
        .chunks(block_size)
        .enumerate()
        .map(|(index, node_ids)| TopologyBlock {
            block_id: format!("block-{:04}", index + 1),
            node_ids: node_ids.to_vec(),
        })
        .collect()
}

fn block_aware_cycle(
    blocks: &[TopologyBlock],
    cycle_index: usize,
    config: &BoundedTopologyConfig,
) -> Vec<NodeId> {
    let mut ordered_blocks = blocks.iter().collect::<Vec<_>>();
    if cycle_index > 0 {
        ordered_blocks.sort_by_cached_key(|block| {
            (
                block_permutation_hash(block, cycle_index, config),
                block.block_id.clone(),
            )
        });
    }

    let mut cycle = Vec::with_capacity(blocks.iter().map(|block| block.node_ids.len()).sum());
    for block in ordered_blocks {
        let mut members = block.node_ids.clone();
        if cycle_index > 0 {
            members.sort_by_cached_key(|node_id| {
                (
                    permutation_hash(node_id, cycle_index, config),
                    node_id.clone(),
                )
            });
        }
        cycle.extend(members);
    }
    cycle
}

fn topology_epoch(node_ids: &[NodeId], config: &BoundedTopologyConfig) -> u64 {
    let mut material = Vec::new();
    append_hash_field(&mut material, TOPOLOGY_ALGORITHM_VERSION.as_bytes());
    append_hash_field(&mut material, config.max_degree.to_string().as_bytes());
    append_hash_field(&mut material, config.block_size.to_string().as_bytes());
    append_hash_field(&mut material, config.permutation_seed.as_bytes());
    append_hash_field(&mut material, node_ids.len().to_string().as_bytes());
    for node_id in node_ids {
        append_hash_field(&mut material, node_id.as_str().as_bytes());
    }
    cryptographic_hash_u64(&material)
}

fn permutation_hash(
    node_id: &NodeId,
    cycle_index: usize,
    config: &BoundedTopologyConfig,
) -> String {
    let mut material = Vec::new();
    append_hash_field(&mut material, b"ipars-bounded-topology-permutation");
    append_hash_field(&mut material, TOPOLOGY_ALGORITHM_VERSION.as_bytes());
    append_hash_field(&mut material, config.permutation_seed.as_bytes());
    append_hash_field(&mut material, cycle_index.to_string().as_bytes());
    append_hash_field(&mut material, node_id.as_str().as_bytes());
    node_id_from_public_key(&material).as_str().to_string()
}

fn block_permutation_hash(
    block: &TopologyBlock,
    cycle_index: usize,
    config: &BoundedTopologyConfig,
) -> String {
    let mut material = Vec::new();
    append_hash_field(&mut material, b"ipars-bounded-topology-block-permutation");
    append_hash_field(&mut material, TOPOLOGY_ALGORITHM_VERSION.as_bytes());
    append_hash_field(&mut material, config.permutation_seed.as_bytes());
    append_hash_field(&mut material, cycle_index.to_string().as_bytes());
    append_hash_field(&mut material, block.block_id.as_bytes());
    for node_id in &block.node_ids {
        append_hash_field(&mut material, node_id.as_str().as_bytes());
    }
    node_id_from_public_key(&material).as_str().to_string()
}

fn append_hash_field(material: &mut Vec<u8>, field: &[u8]) {
    material.extend_from_slice(&(field.len() as u64).to_be_bytes());
    material.extend_from_slice(field);
}

fn cryptographic_hash_u64(material: &[u8]) -> u64 {
    let digest = node_id_from_public_key(material);
    digest
        .as_str()
        .strip_prefix("node-")
        .and_then(|hex| hex.get(..16))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .unwrap_or(0)
}

fn add_hamiltonian_cycle(
    adjacency: &mut BTreeMap<NodeId, BTreeSet<NodeId>>,
    edge_cycles: &mut BTreeMap<TopologyEdge, BTreeSet<usize>>,
    cycle: &[NodeId],
    cycle_index: usize,
) {
    if cycle.len() < 2 {
        return;
    }
    for index in 0..cycle.len() {
        let first = &cycle[index];
        let second = &cycle[(index + 1) % cycle.len()];
        add_undirected_edge(adjacency, first, second);
        if let Some(edge) = TopologyEdge::new(first.clone(), second.clone()) {
            edge_cycles.entry(edge).or_default().insert(cycle_index);
        }
    }
}

fn add_undirected_edge(
    adjacency: &mut BTreeMap<NodeId, BTreeSet<NodeId>>,
    first: &NodeId,
    second: &NodeId,
) {
    if first == second {
        return;
    }
    if let Some(neighbors) = adjacency.get_mut(first) {
        neighbors.insert(second.clone());
    }
    if let Some(neighbors) = adjacency.get_mut(second) {
        neighbors.insert(first.clone());
    }
}

fn predecessor_tree_from(
    source: &NodeId,
    adjacency: &BTreeMap<NodeId, BTreeSet<NodeId>>,
) -> BTreeMap<NodeId, NodeId> {
    let mut predecessors = BTreeMap::new();
    let mut visited = BTreeSet::from([source.clone()]);
    let mut queue = VecDeque::from([source.clone()]);
    while let Some(current) = queue.pop_front() {
        let Some(neighbors) = adjacency.get(&current) else {
            continue;
        };
        for neighbor in neighbors {
            if !visited.insert(neighbor.clone()) {
                continue;
            }
            predecessors.insert(neighbor.clone(), current.clone());
            queue.push_back(neighbor.clone());
        }
    }
    predecessors
}

fn inspect_invariants(
    adjacency: &BTreeMap<NodeId, BTreeSet<NodeId>>,
    max_degree: usize,
) -> TopologyInvariants {
    let no_self_loops = adjacency
        .iter()
        .all(|(node_id, neighbors)| !neighbors.contains(node_id));
    let symmetric = adjacency.iter().all(|(node_id, neighbors)| {
        neighbors.iter().all(|neighbor| {
            adjacency
                .get(neighbor)
                .is_some_and(|reverse| reverse.contains(node_id))
        })
    });
    let max_observed_degree = adjacency.values().map(BTreeSet::len).max().unwrap_or(0);
    let edge_count = adjacency
        .iter()
        .flat_map(|(node_id, neighbors)| {
            neighbors
                .iter()
                .filter_map(|neighbor| TopologyEdge::new(node_id.clone(), neighbor.clone()))
        })
        .collect::<BTreeSet<_>>()
        .len();

    TopologyInvariants {
        node_count: adjacency.len(),
        edge_count,
        max_observed_degree,
        connected: graph_is_connected(adjacency),
        symmetric,
        no_self_loops,
        within_degree_bound: max_observed_degree <= max_degree,
    }
}

fn graph_is_connected(adjacency: &BTreeMap<NodeId, BTreeSet<NodeId>>) -> bool {
    let Some(start) = adjacency.keys().next() else {
        return true;
    };
    distances_from(start, adjacency).len() == adjacency.len()
}

fn distances_from(
    source: &NodeId,
    adjacency: &BTreeMap<NodeId, BTreeSet<NodeId>>,
) -> BTreeMap<NodeId, usize> {
    let mut distances = BTreeMap::from([(source.clone(), 0)]);
    let mut queue = VecDeque::from([source.clone()]);

    while let Some(current) = queue.pop_front() {
        let Some(distance) = distances.get(&current).copied() else {
            continue;
        };
        let Some(neighbors) = adjacency.get(&current) else {
            continue;
        };
        for neighbor in neighbors {
            if distances.contains_key(neighbor) {
                continue;
            }
            distances.insert(neighbor.clone(), distance + 1);
            queue.push_back(neighbor.clone());
        }
    }
    distances
}

fn edge_is_unavailable(
    first: &NodeId,
    second: &NodeId,
    unavailable_edges: &BTreeSet<TopologyEdge>,
) -> bool {
    TopologyEdge::new(first.clone(), second.clone())
        .is_some_and(|edge| unavailable_edges.contains(&edge))
}

fn path_edges(path: &[NodeId]) -> BTreeSet<TopologyEdge> {
    path.windows(2)
        .filter_map(|nodes| TopologyEdge::new(nodes[0].clone(), nodes[1].clone()))
        .collect()
}

fn reconstruct_path(
    source: &NodeId,
    destination: &NodeId,
    predecessor: &BTreeMap<NodeId, NodeId>,
) -> Option<Vec<NodeId>> {
    let mut reversed = vec![destination.clone()];
    let mut cursor = destination;
    while cursor != source {
        cursor = predecessor.get(cursor)?;
        reversed.push(cursor.clone());
    }
    reversed.reverse();
    Some(reversed)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use chrono::Utc;
    use ipars_types::{ClusterId, Role, TokenPolicy, VpnIp};

    use super::*;

    #[test]
    fn one_node_has_zero_degree_and_a_local_path() {
        let nodes = records(1);
        let topology = topology(&nodes, 4);
        let node_id = &nodes[0].node_id;

        assert_eq!(topology.invariants().node_count, 1);
        assert_eq!(topology.invariants().edge_count, 0);
        assert_eq!(topology.invariants().max_observed_degree, 0);
        assert!(topology.invariants().are_satisfied());
        assert_eq!(topology.diameter(), Some(0));
        assert_eq!(
            topology.shortest_path(node_id, node_id),
            Some(vec![node_id.clone()])
        );
        assert_eq!(
            topology.paths(node_id, node_id),
            Some(TopologyPaths {
                primary: vec![node_id.clone()],
                secondary: None,
            })
        );
    }

    #[test]
    fn two_nodes_have_one_deduplicated_edge() {
        let nodes = records(2);
        let topology = topology(&nodes, 6);

        assert_eq!(topology.invariants().node_count, 2);
        assert_eq!(topology.invariants().edge_count, 1);
        assert_eq!(topology.invariants().max_observed_degree, 1);
        assert_eq!(topology.diameter(), Some(1));
        let paths = topology.paths(&nodes[0].node_id, &nodes[1].node_id);
        let Some(paths) = paths else {
            panic!("two connected nodes must have a path");
        };
        assert_eq!(paths.primary.len(), 2);
        assert_eq!(paths.secondary, None);
    }

    #[test]
    fn five_nodes_are_connected_and_respect_both_degree_limits() {
        let nodes = records(5);
        for max_degree in SUPPORTED_MAX_DEGREES {
            let topology = topology(&nodes, max_degree);
            assert!(topology.invariants().are_satisfied());
            assert_eq!(topology.invariants().node_count, 5);
            assert!(topology.invariants().max_observed_degree <= max_degree);
            assert!(topology
                .adjacency()
                .values()
                .all(|neighbors| neighbors.len() <= max_degree));
        }
    }

    #[test]
    fn deterministic_output_is_independent_of_input_order() {
        let nodes = records(128);
        let mut reversed = nodes.clone();
        reversed.reverse();
        let config = BoundedTopologyConfig::new(6)
            .with_block_size(7)
            .with_permutation_seed("cluster-a");

        let first = synthesize_bounded_topology(&nodes, &config);
        let second = synthesize_bounded_topology(&reversed, &config);
        assert_eq!(first, second);
    }

    #[test]
    fn blocks_partition_membership_and_mark_redundant_boundary_cycles() {
        let nodes = records(10);
        let topology = topology_with_config(
            &nodes,
            &BoundedTopologyConfig::new(4)
                .with_block_size(3)
                .with_permutation_seed("cluster-a"),
        );

        assert_eq!(topology.block_size(), 3);
        assert_eq!(
            topology
                .blocks()
                .iter()
                .map(|block| block.node_ids().len())
                .collect::<Vec<_>>(),
            vec![3, 3, 3, 1]
        );
        let members = topology
            .blocks()
            .iter()
            .flat_map(|block| block.node_ids().iter().cloned())
            .collect::<BTreeSet<_>>();
        assert_eq!(members.len(), nodes.len());

        let block_by_node = topology
            .blocks()
            .iter()
            .flat_map(|block| {
                block
                    .node_ids()
                    .iter()
                    .map(|node_id| (node_id.clone(), block.block_id().to_string()))
            })
            .collect::<BTreeMap<_, _>>();
        let crossing_cycles = topology
            .edge_cycles()
            .iter()
            .filter(|(edge, _)| block_by_node[edge.first()] != block_by_node[edge.second()])
            .flat_map(|(_, cycles)| cycles.iter().copied())
            .collect::<BTreeSet<_>>();
        assert_eq!(crossing_cycles, BTreeSet::from([0, 1]));
    }

    #[test]
    fn changing_block_size_advances_epoch_and_changes_secondary_layout() {
        let nodes = records(128);
        let small_blocks = topology_with_config(
            &nodes,
            &BoundedTopologyConfig::new(4)
                .with_block_size(4)
                .with_permutation_seed("cluster-a"),
        );
        let large_blocks = topology_with_config(
            &nodes,
            &BoundedTopologyConfig::new(4)
                .with_block_size(16)
                .with_permutation_seed("cluster-a"),
        );

        assert_ne!(small_blocks.topology_epoch(), large_blocks.topology_epoch());
        assert_ne!(small_blocks.edge_cycles(), large_blocks.edge_cycles());
        assert_eq!(small_blocks.blocks().len(), 32);
        assert_eq!(large_blocks.blocks().len(), 8);
        assert!(small_blocks.invariants().are_satisfied());
        assert!(large_blocks.invariants().are_satisfied());
    }

    #[test]
    fn supported_block_sizes_remain_bounded_at_one_thousand_nodes() {
        let nodes = records(1_000);
        for block_size in [2, 4, 8, 16, 32, 64] {
            let topology = topology_with_config(
                &nodes,
                &BoundedTopologyConfig::new(4)
                    .with_block_size(block_size)
                    .with_permutation_seed("cluster-a"),
            );
            assert!(topology.invariants().are_satisfied());
            assert!(topology.invariants().max_observed_degree <= 4);
            assert!(topology.diameter().is_some());
        }
    }

    #[test]
    fn one_thousand_nodes_have_bounded_degree_and_logarithmicish_diameter() {
        let nodes = records(1_000);
        for max_degree in SUPPORTED_MAX_DEGREES {
            let topology = topology(&nodes, max_degree);
            assert!(topology.invariants().are_satisfied());
            assert_eq!(topology.invariants().node_count, 1_000);
            assert!(topology.invariants().max_observed_degree <= max_degree);

            let diameter = topology.diameter();
            let Some(diameter) = diameter else {
                panic!("a synthesized topology must be connected");
            };
            let logarithmicish_limit = 2 * (usize::BITS - 1_000_usize.leading_zeros()) as usize;
            assert!(
                diameter <= logarithmicish_limit,
                "degree {max_degree} topology diameter {diameter} exceeds {logarithmicish_limit}"
            );
        }
    }

    #[test]
    fn bounded_next_hop_table_matches_disjoint_paths_at_one_thousand_nodes() {
        let nodes = records(1_000);
        for max_degree in SUPPORTED_MAX_DEGREES {
            let topology = topology(&nodes, max_degree);
            let source = &nodes[17].node_id;
            let Some(neighbors) = topology.neighbors(source) else {
                panic!("source must be present in synthesized topology");
            };
            let started = Instant::now();
            let Some(next_hops) = topology.next_hops_from(source) else {
                panic!("source must have a next-hop table");
            };
            let table_elapsed = started.elapsed();

            assert_eq!(next_hops.len(), nodes.len() - 1);
            for destination in topology.adjacency().keys().filter(|node| *node != source) {
                let Some(paths) = topology.paths(source, destination) else {
                    panic!("synthesized topology must provide paths");
                };
                let Some((primary, secondary)) = next_hops.get(destination) else {
                    panic!("every remote node must have next hops");
                };
                assert_eq!(Some(primary), paths.primary.get(1));
                assert!(neighbors.contains(primary));
                let Some(secondary_path) = paths.secondary.as_ref() else {
                    panic!("cycle-union topology must retain an alternate first hop");
                };
                assert_eq!(secondary.as_ref(), secondary_path.nodes.get(1));
                let Some(secondary) = secondary.as_ref() else {
                    panic!("next-hop table must retain the alternate first hop");
                };
                assert!(neighbors.contains(secondary));
                assert_ne!(secondary, primary);
                assert!(
                    path_edges(&paths.primary).is_disjoint(&path_edges(&secondary_path.nodes)),
                    "degree {max_degree} paths to {destination} share an edge"
                );
            }
            eprintln!(
                "degree {max_degree}: built {} destinations in {:?}, verified in {:?}",
                next_hops.len(),
                table_elapsed,
                started.elapsed()
            );
        }
    }

    #[test]
    fn membership_and_config_changes_advance_the_epoch() {
        let nodes = records(5);
        let reordered = nodes.iter().cloned().rev().collect::<Vec<_>>();
        let expanded = records(6);
        let config = BoundedTopologyConfig::new(4).with_permutation_seed("cluster-a");

        let initial = topology_with_config(&nodes, &config);
        let same_membership = topology_with_config(&reordered, &config);
        let changed_membership = topology_with_config(&expanded, &config);
        let changed_degree = topology_with_config(
            &nodes,
            &BoundedTopologyConfig::new(6).with_permutation_seed("cluster-a"),
        );
        let changed_seed = topology_with_config(
            &nodes,
            &BoundedTopologyConfig::new(4).with_permutation_seed("cluster-b"),
        );

        assert_eq!(initial.topology_epoch(), same_membership.topology_epoch());
        assert_ne!(
            initial.topology_epoch(),
            changed_membership.topology_epoch()
        );
        assert_ne!(initial.topology_epoch(), changed_degree.topology_epoch());
        assert_ne!(initial.topology_epoch(), changed_seed.topology_epoch());
    }

    #[test]
    fn secondary_path_survives_primary_edge_failures() {
        let nodes = records(64);
        let topology = topology(&nodes, 4);
        let paths = topology.paths(&nodes[0].node_id, &nodes[32].node_id);
        let Some(paths) = paths else {
            panic!("connected topology must produce primary paths");
        };
        let Some(secondary) = paths.secondary else {
            panic!("Hamiltonian-cycle union must provide an alternate route");
        };
        let failed_edges = path_edges(&paths.primary);
        let rerouted = topology.shortest_path_avoiding(
            &nodes[0].node_id,
            &nodes[32].node_id,
            &BTreeSet::new(),
            &failed_edges,
        );

        assert_eq!(rerouted, Some(secondary.nodes.clone()));
        assert!(path_edges(&paths.primary).is_disjoint(&path_edges(&secondary.nodes)));
    }

    #[test]
    fn vertex_disjoint_secondary_survives_primary_node_failures() {
        let nodes = records(64);
        let topology = topology(&nodes, 6);
        let candidate = nodes.iter().enumerate().find_map(|(source_index, source)| {
            nodes.iter().skip(source_index + 1).find_map(|destination| {
                let paths = topology.paths(&source.node_id, &destination.node_id)?;
                let secondary = paths.secondary.as_ref()?;
                if paths.primary.len() > 2 && secondary.kind == SecondaryPathKind::VertexDisjoint {
                    Some((source.node_id.clone(), destination.node_id.clone(), paths))
                } else {
                    None
                }
            })
        });
        let Some((source, destination, paths)) = candidate else {
            panic!("expected a non-trivial vertex-disjoint path pair");
        };
        let failed_nodes = paths
            .primary
            .iter()
            .skip(1)
            .take(paths.primary.len() - 2)
            .cloned()
            .collect::<BTreeSet<_>>();
        let rerouted =
            topology.shortest_path_avoiding(&source, &destination, &failed_nodes, &BTreeSet::new());
        let Some(rerouted) = rerouted else {
            panic!("node failure must leave an alternate path");
        };
        assert!(rerouted.iter().all(|node| !failed_nodes.contains(node)));
        let secondary_nodes = paths
            .secondary
            .as_ref()
            .map(|path| {
                path.nodes
                    .iter()
                    .skip(1)
                    .take(path.nodes.len().saturating_sub(2))
                    .cloned()
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        assert!(failed_nodes.is_disjoint(&secondary_nodes));
    }

    #[test]
    fn invalid_config_and_duplicate_membership_are_rejected() {
        let nodes = records(2);
        assert_eq!(
            synthesize_bounded_topology(&nodes, &BoundedTopologyConfig::new(5)),
            Err(BoundedTopologyError::UnsupportedMaxDegree { max_degree: 5 })
        );
        for block_size in [1, 65] {
            assert_eq!(
                synthesize_bounded_topology(
                    &nodes,
                    &BoundedTopologyConfig::new(4).with_block_size(block_size)
                ),
                Err(BoundedTopologyError::InvalidBlockSize {
                    block_size,
                    minimum: 2,
                    maximum: 64,
                })
            );
        }

        let duplicate = vec![nodes[0].clone(), nodes[0].clone()];
        assert_eq!(
            synthesize_bounded_topology(&duplicate, &BoundedTopologyConfig::new(4)),
            Err(BoundedTopologyError::DuplicateNodeId {
                node_id: nodes[0].node_id.clone(),
            })
        );
    }

    fn topology(nodes: &[NodeRecord], max_degree: usize) -> BoundedTopology {
        topology_with_config(nodes, &BoundedTopologyConfig::new(max_degree))
    }

    fn topology_with_config(
        nodes: &[NodeRecord],
        config: &BoundedTopologyConfig,
    ) -> BoundedTopology {
        match synthesize_bounded_topology(nodes, config) {
            Ok(topology) => topology,
            Err(error) => panic!("topology synthesis failed: {error}"),
        }
    }

    fn records(count: usize) -> Vec<NodeRecord> {
        (0..count).map(node_record).collect()
    }

    fn node_record(index: usize) -> NodeRecord {
        let third_octet = ((index / 254) % 256) as u8;
        let fourth_octet = (index % 254 + 1) as u8;
        NodeRecord {
            node_id: NodeId::from_string(format!("node-{index:04}")),
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(
                10,
                250,
                third_octet,
                fourth_octet,
            ))),
            identity_public_key: format!("identity-{index:04}"),
            wireguard_public_key: format!("wireguard-{index:04}"),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }
}
