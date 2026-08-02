//! Deterministic recursive bounded-degree topology synthesis for the relay backbone.
//!
//! Membership is placed in a hash-prefix hierarchy. Leaves contain at most the
//! configured fanout, internal groups contain at most that many child groups,
//! and every non-root group exposes two deterministic ports to its parent.
//! Leaf cycles consume at most two physical links per node. Parent groups join
//! each child's secondary port to the next child's primary port, so each port
//! consumes one more link and the parent-level block ring survives one failed
//! representative as a path.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use ipars_crypto::node_id_from_public_key;
use ipars_types::{
    NodeId, NodeRecord, DEFAULT_OVERLAY_BLOCK_SIZE, MAX_OVERLAY_BLOCK_SIZE, MIN_OVERLAY_BLOCK_SIZE,
};
use thiserror::Error;

pub const TOPOLOGY_ALGORITHM_VERSION: &str = "recursive-hash-prefix-block-ring-v3";
const DEFAULT_PERMUTATION_SEED: &str = "ipars-bounded-backbone";
const MIN_HIERARCHICAL_BLOCK_SIZE: usize = 4;
const MAX_HASH_PREFIX_PROBES: usize = 256;

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
        Self::new(4)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TopologyEdge {
    first: NodeId,
    second: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyGroup {
    group_id: String,
    node_ids: Vec<NodeId>,
    parent_group_id: Option<String>,
    child_group_ids: Vec<String>,
    depth: usize,
    representatives: Vec<TopologyRepresentative>,
}

impl TopologyGroup {
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    pub fn node_ids(&self) -> &[NodeId] {
        &self.node_ids
    }

    pub fn parent_group_id(&self) -> Option<&str> {
        self.parent_group_id.as_deref()
    }

    pub fn child_group_ids(&self) -> &[String] {
        &self.child_group_ids
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn representatives(&self) -> &[TopologyRepresentative] {
        &self.representatives
    }

    pub fn is_leaf(&self) -> bool {
        self.child_group_ids.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyRepresentative {
    node_id: NodeId,
    plane: usize,
}

impl TopologyRepresentative {
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    pub fn plane(&self) -> usize {
        self.plane
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TopologyEdgeKind {
    LeafCycle,
    HierarchyLink,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TopologyEdgePlacement {
    level: usize,
    plane: usize,
    kind: TopologyEdgeKind,
    group_id: String,
}

impl TopologyEdgePlacement {
    pub fn level(&self) -> usize {
        self.level
    }

    pub fn plane(&self) -> usize {
        self.plane
    }

    pub fn kind(&self) -> TopologyEdgeKind {
        self.kind
    }

    pub fn group_id(&self) -> &str {
        &self.group_id
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
    #[error("could not allocate two bounded-degree representatives for group {group_id}")]
    RepresentativeCapacity { group_id: String },
}

#[derive(Debug, Clone)]
pub struct BoundedTopology {
    topology_epoch: u64,
    max_degree: usize,
    fanout: usize,
    groups: Vec<TopologyGroup>,
    edge_placements: BTreeMap<TopologyEdge, BTreeSet<TopologyEdgePlacement>>,
    adjacency: BTreeMap<NodeId, BTreeSet<NodeId>>,
    invariants: TopologyInvariants,
    diameter_lower_bound: Option<usize>,
    routing_node_ids: Vec<NodeId>,
    routing_node_indexes: BTreeMap<NodeId, usize>,
    indexed_adjacency: Vec<Vec<usize>>,
    next_hop_cache: Arc<NextHopCache>,
    path_cache: Arc<SourcePathCache>,
}

impl PartialEq for BoundedTopology {
    fn eq(&self, other: &Self) -> bool {
        self.topology_epoch == other.topology_epoch
            && self.max_degree == other.max_degree
            && self.fanout == other.fanout
            && self.groups == other.groups
            && self.edge_placements == other.edge_placements
            && self.adjacency == other.adjacency
            && self.invariants == other.invariants
            && self.diameter_lower_bound == other.diameter_lower_bound
            && self.routing_node_ids == other.routing_node_ids
            && self.routing_node_indexes == other.routing_node_indexes
            && self.indexed_adjacency == other.indexed_adjacency
    }
}

impl Eq for BoundedTopology {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompactNextHops {
    primary: u32,
    secondary: Option<u32>,
}

#[derive(Debug, Default)]
struct NextHopCache {
    by_source: StdMutex<BTreeMap<usize, Arc<Vec<Option<CompactNextHops>>>>>,
}

#[derive(Debug)]
struct SourcePathCache {
    by_source: Vec<OnceLock<Arc<CachedSourcePaths>>>,
    #[cfg(test)]
    source_build_count: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    pair_build_count: std::sync::atomic::AtomicUsize,
}

impl SourcePathCache {
    fn new(node_count: usize) -> Self {
        Self {
            by_source: std::iter::repeat_with(OnceLock::new)
                .take(node_count)
                .collect(),
            #[cfg(test)]
            source_build_count: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            pair_build_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[derive(Debug)]
struct CachedSourcePaths {
    predecessors: Box<[Option<usize>]>,
    by_destination: Vec<OnceLock<Option<IndexedTopologyPaths>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedTopologyPaths {
    primary: Box<[usize]>,
    secondary: Option<IndexedSecondaryPath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedSecondaryPath {
    kind: SecondaryPathKind,
    nodes: Box<[usize]>,
}

impl IndexedTopologyPaths {
    fn from_paths(paths: TopologyPaths, node_indexes: &BTreeMap<NodeId, usize>) -> Option<Self> {
        let primary = index_path(&paths.primary, node_indexes)?;
        let secondary = match paths.secondary {
            Some(secondary) => Some(IndexedSecondaryPath {
                kind: secondary.kind,
                nodes: index_path(&secondary.nodes, node_indexes)?,
            }),
            None => None,
        };
        Some(Self { primary, secondary })
    }

    fn materialize(&self, node_ids: &[NodeId]) -> Option<TopologyPaths> {
        let primary = materialize_indexed_path(&self.primary, node_ids)?;
        let secondary = match self.secondary.as_ref() {
            Some(secondary) => Some(SecondaryPath {
                kind: secondary.kind,
                nodes: materialize_indexed_path(&secondary.nodes, node_ids)?,
            }),
            None => None,
        };
        Some(TopologyPaths { primary, secondary })
    }
}

pub(crate) struct TopologyNextHopTable<'a> {
    topology: &'a BoundedTopology,
    compact: Arc<Vec<Option<CompactNextHops>>>,
}

impl TopologyNextHopTable<'_> {
    pub(crate) fn get(&self, destination: &NodeId) -> Option<(NodeId, Option<NodeId>)> {
        let destination_index = *self.topology.routing_node_indexes.get(destination)?;
        let next_hops = self.compact.get(destination_index)?.as_ref()?;
        let primary = self
            .topology
            .routing_node_ids
            .get(next_hops.primary as usize)?
            .clone();
        let secondary = next_hops
            .secondary
            .and_then(|index| self.topology.routing_node_ids.get(index as usize).cloned());
        Some((primary, secondary))
    }
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
        let minimum_block_size =
            usize::from(MIN_OVERLAY_BLOCK_SIZE).max(MIN_HIERARCHICAL_BLOCK_SIZE);
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
        let mut hierarchy = build_hierarchy(&node_ids, config)?;
        let mut adjacency = node_ids
            .iter()
            .cloned()
            .map(|node_id| (node_id, BTreeSet::new()))
            .collect::<BTreeMap<_, _>>();
        let mut edge_placements = BTreeMap::<TopologyEdge, BTreeSet<TopologyEdgePlacement>>::new();
        let mut reserved_representative_degree = BTreeMap::new();

        add_leaf_cycles(&hierarchy, &mut adjacency, &mut edge_placements);
        allocate_representatives_and_hierarchy_edges(
            &mut hierarchy,
            config,
            &mut reserved_representative_degree,
            &mut adjacency,
            &mut edge_placements,
        )?;

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
        if !graph_has_no_articulation_points(&adjacency) {
            return Err(BoundedTopologyError::InvariantViolation {
                reason: "a single node failure disconnects the remaining graph",
            });
        }
        let diameter_lower_bound = calculate_diameter_lower_bound(&adjacency);
        let groups: Vec<TopologyGroup> = hierarchy
            .into_iter()
            .map(HierarchyGroup::into_group)
            .collect();
        let routing_node_ids = node_ids;
        let routing_node_indexes = routing_node_ids
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, node_id)| (node_id, index))
            .collect::<BTreeMap<_, _>>();
        let indexed_adjacency = routing_node_ids
            .iter()
            .map(|node_id| {
                adjacency
                    .get(node_id)
                    .into_iter()
                    .flatten()
                    .filter_map(|neighbor| routing_node_indexes.get(neighbor).copied())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let routing_node_count = routing_node_ids.len();

        Ok(Self {
            topology_epoch,
            max_degree: config.max_degree,
            fanout: config.block_size,
            groups,
            edge_placements,
            adjacency,
            invariants,
            diameter_lower_bound,
            routing_node_ids,
            routing_node_indexes,
            indexed_adjacency,
            next_hop_cache: Arc::new(NextHopCache::default()),
            path_cache: Arc::new(SourcePathCache::new(routing_node_count)),
        })
    }

    pub fn topology_epoch(&self) -> u64 {
        self.topology_epoch
    }

    pub fn max_degree(&self) -> usize {
        self.max_degree
    }

    pub fn fanout(&self) -> usize {
        self.fanout
    }

    pub fn groups(&self) -> &[TopologyGroup] {
        &self.groups
    }

    pub fn edge_placements(&self) -> &BTreeMap<TopologyEdge, BTreeSet<TopologyEdgePlacement>> {
        &self.edge_placements
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
        let source_index = *self.routing_node_indexes.get(source)?;
        let destination_index = *self.routing_node_indexes.get(destination)?;
        let source_paths = self.cached_paths_from(source_index)?;
        source_paths
            .by_destination
            .get(destination_index)?
            .get_or_init(|| {
                #[cfg(test)]
                self.path_cache
                    .pair_build_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.compute_pair_paths(source_index, destination_index, &source_paths.predecessors)
            })
            .as_ref()?
            .materialize(&self.routing_node_ids)
    }

    pub fn paths_avoiding(
        &self,
        source: &NodeId,
        destination: &NodeId,
        unavailable_nodes: &BTreeSet<NodeId>,
    ) -> Option<TopologyPaths> {
        let primary =
            self.shortest_path_avoiding(source, destination, unavailable_nodes, &BTreeSet::new())?;
        if source == destination {
            return Some(TopologyPaths {
                primary,
                secondary: None,
            });
        }

        let primary_edges = path_edges(&primary);
        let mut unavailable_for_secondary = unavailable_nodes.clone();
        unavailable_for_secondary.extend(
            primary
                .iter()
                .skip(1)
                .take(primary.len().saturating_sub(2))
                .cloned(),
        );
        let secondary = self
            .shortest_path_avoiding(
                source,
                destination,
                &unavailable_for_secondary,
                &primary_edges,
            )
            .map(|nodes| SecondaryPath {
                kind: SecondaryPathKind::VertexDisjoint,
                nodes,
            })
            .or_else(|| {
                self.shortest_path_avoiding(source, destination, unavailable_nodes, &primary_edges)
                    .map(|nodes| SecondaryPath {
                        kind: SecondaryPathKind::EdgeDisjoint,
                        nodes,
                    })
            });

        Some(TopologyPaths { primary, secondary })
    }

    #[cfg(test)]
    fn uncached_paths(&self, source: &NodeId, destination: &NodeId) -> Option<TopologyPaths> {
        let primary = self.shortest_path(source, destination)?;
        Some(self.paths_from_primary(source, destination, primary))
    }

    fn paths_from_primary(
        &self,
        source: &NodeId,
        destination: &NodeId,
        primary: Vec<NodeId>,
    ) -> TopologyPaths {
        if source == destination {
            return TopologyPaths {
                primary,
                secondary: None,
            };
        }

        let secondary = self.secondary_path(source, destination, &primary);
        if secondary
            .as_ref()
            .is_some_and(|path| path.kind == SecondaryPathKind::VertexDisjoint)
        {
            return TopologyPaths { primary, secondary };
        }
        if let Some((primary, secondary)) =
            two_internally_vertex_disjoint_paths(&self.adjacency, source, destination)
        {
            return TopologyPaths {
                primary,
                secondary: Some(SecondaryPath {
                    kind: SecondaryPathKind::VertexDisjoint,
                    nodes: secondary,
                }),
            };
        }

        TopologyPaths { primary, secondary }
    }

    fn cached_paths_from(&self, source_index: usize) -> Option<Arc<CachedSourcePaths>> {
        let slot = self.path_cache.by_source.get(source_index)?;
        Some(
            slot.get_or_init(|| {
                #[cfg(test)]
                self.path_cache
                    .source_build_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Arc::new(self.compute_paths_from(source_index))
            })
            .clone(),
        )
    }

    fn compute_paths_from(&self, source_index: usize) -> CachedSourcePaths {
        let predecessors = self
            .indexed_shortest_path_predecessors(source_index)
            .unwrap_or_default()
            .into_boxed_slice();
        let by_destination = std::iter::repeat_with(OnceLock::new)
            .take(self.routing_node_ids.len())
            .collect();
        CachedSourcePaths {
            predecessors,
            by_destination,
        }
    }

    fn compute_pair_paths(
        &self,
        source_index: usize,
        destination_index: usize,
        predecessors: &[Option<usize>],
    ) -> Option<IndexedTopologyPaths> {
        let source = self.routing_node_ids.get(source_index)?;
        let destination = self.routing_node_ids.get(destination_index)?;
        let primary = reconstruct_indexed_path(source_index, destination_index, predecessors)?;
        let primary = materialize_indexed_path(&primary, &self.routing_node_ids)?;
        IndexedTopologyPaths::from_paths(
            self.paths_from_primary(source, destination, primary),
            &self.routing_node_indexes,
        )
    }

    fn indexed_shortest_path_predecessors(
        &self,
        source_index: usize,
    ) -> Option<Vec<Option<usize>>> {
        self.indexed_adjacency.get(source_index)?;
        let mut predecessors = vec![None; self.indexed_adjacency.len()];
        predecessors[source_index] = Some(source_index);
        let mut queue = VecDeque::from([source_index]);
        while let Some(current) = queue.pop_front() {
            for &neighbor in &self.indexed_adjacency[current] {
                if predecessors[neighbor].is_some() {
                    continue;
                }
                predecessors[neighbor] = Some(current);
                queue.push_back(neighbor);
            }
        }
        Some(predecessors)
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

    pub(crate) fn next_hop_table(&self, source: &NodeId) -> Option<TopologyNextHopTable<'_>> {
        let source_index = *self.routing_node_indexes.get(source)?;
        let compact = self.cached_next_hops_from(source_index)?;
        Some(TopologyNextHopTable {
            topology: self,
            compact,
        })
    }

    /// Compute primary and alternate first hops. The alternate route never uses
    /// the primary first-hop node as an internal vertex, so it remains usable
    /// after that neighbor fails.
    pub fn next_hops_from(
        &self,
        source: &NodeId,
    ) -> Option<BTreeMap<NodeId, (NodeId, Option<NodeId>)>> {
        let table = self.next_hop_table(source)?;
        let mut next_hops = BTreeMap::new();
        for destination in &self.routing_node_ids {
            if let Some(hops) = table.get(destination) {
                next_hops.insert(destination.clone(), hops);
            }
        }
        Some(next_hops)
    }

    fn cached_next_hops_from(
        &self,
        source_index: usize,
    ) -> Option<Arc<Vec<Option<CompactNextHops>>>> {
        if let Some(cached) = self
            .next_hop_cache
            .by_source
            .lock()
            .ok()?
            .get(&source_index)
            .cloned()
        {
            return Some(cached);
        }
        let computed = Arc::new(self.compute_next_hops_from(source_index)?);
        let mut cache = self.next_hop_cache.by_source.lock().ok()?;
        Some(
            cache
                .entry(source_index)
                .or_insert_with(|| computed.clone())
                .clone(),
        )
    }

    fn compute_next_hops_from(&self, source_index: usize) -> Option<Vec<Option<CompactNextHops>>> {
        let source_neighbors = self.indexed_adjacency.get(source_index)?;
        let candidate_distances = source_neighbors
            .iter()
            .filter_map(|neighbor| {
                Some((
                    u32::try_from(*neighbor).ok()?,
                    self.indexed_distances_from_avoiding(*neighbor, source_index),
                ))
            })
            .collect::<Vec<_>>();
        let alternate_labels = source_neighbors
            .iter()
            .filter_map(|neighbor| {
                Some((
                    u32::try_from(*neighbor).ok()?,
                    self.alternate_first_hop_labels(source_index, *neighbor),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        let mut table = vec![None; self.routing_node_ids.len()];
        for destination_index in 0..self.routing_node_ids.len() {
            if destination_index == source_index {
                continue;
            }
            let mut candidates = candidate_distances
                .iter()
                .filter_map(|(neighbor, distances)| {
                    distances[destination_index].map(|distance| (distance + 1, *neighbor))
                })
                .collect::<Vec<_>>();
            candidates.sort();
            let fallback_primary = candidates.first().map(|(_, neighbor)| *neighbor)?;
            let reliable = candidates.into_iter().find_map(|(_, primary)| {
                let secondary = alternate_labels
                    .get(&primary)?
                    .get(destination_index)?
                    .filter(|secondary| *secondary != primary)?;
                Some((primary, secondary))
            });
            let (primary, secondary) = reliable
                .map(|(primary, secondary)| (primary, Some(secondary)))
                .unwrap_or((fallback_primary, None));
            table[destination_index] = Some(CompactNextHops { primary, secondary });
        }
        Some(table)
    }

    fn indexed_distances_from_avoiding(
        &self,
        source_index: usize,
        unavailable_index: usize,
    ) -> Vec<Option<u32>> {
        let mut distances = vec![None; self.routing_node_ids.len()];
        distances[source_index] = Some(0_u32);
        let mut queue = VecDeque::from([source_index]);
        while let Some(current) = queue.pop_front() {
            let Some(distance) = distances[current] else {
                continue;
            };
            for &neighbor in &self.indexed_adjacency[current] {
                if neighbor == unavailable_index || distances[neighbor].is_some() {
                    continue;
                }
                let Some(next_distance) = distance.checked_add(1) else {
                    continue;
                };
                distances[neighbor] = Some(next_distance);
                queue.push_back(neighbor);
            }
        }
        distances
    }

    fn alternate_first_hop_labels(
        &self,
        source_index: usize,
        terminal_index: usize,
    ) -> Vec<Option<u32>> {
        let mut labels = vec![None; self.routing_node_ids.len()];
        let mut queue = VecDeque::new();
        for &neighbor in &self.indexed_adjacency[source_index] {
            if neighbor == terminal_index {
                continue;
            }
            let Ok(label) = u32::try_from(neighbor) else {
                return labels;
            };
            labels[neighbor] = Some(label);
            queue.push_back(neighbor);
        }
        while let Some(current) = queue.pop_front() {
            if current == terminal_index {
                continue;
            }
            let Some(label) = labels[current] else {
                continue;
            };
            for &neighbor in &self.indexed_adjacency[current] {
                if neighbor == source_index || labels[neighbor].is_some() {
                    continue;
                }
                labels[neighbor] = Some(label);
                queue.push_back(neighbor);
            }
        }
        labels
    }

    #[cfg(test)]
    fn cached_next_hop_source_count(&self) -> usize {
        self.next_hop_cache
            .by_source
            .lock()
            .map(|cache| cache.len())
            .unwrap_or(0)
    }

    #[cfg(test)]
    fn cached_path_source_count(&self) -> usize {
        self.path_cache
            .by_source
            .iter()
            .filter(|slot| slot.get().is_some())
            .count()
    }

    #[cfg(test)]
    fn path_cache_slot_count(&self) -> usize {
        self.path_cache.by_source.len()
    }

    #[cfg(test)]
    fn path_cache_build_count(&self) -> usize {
        self.path_cache
            .source_build_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    fn path_cache_pair_build_count(&self) -> usize {
        self.path_cache
            .pair_build_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    fn cached_path_destination_count(&self, source: &NodeId) -> usize {
        self.routing_node_indexes
            .get(source)
            .and_then(|source_index| self.path_cache.by_source.get(*source_index))
            .and_then(OnceLock::get)
            .map(|source_paths| {
                source_paths
                    .by_destination
                    .iter()
                    .filter(|slot| slot.get().is_some())
                    .count()
            })
            .unwrap_or(0)
    }

    /// Returns a cached lower bound from deterministic repeated farthest-node
    /// sweeps, or `None` for an empty or disconnected graph.
    pub fn diameter_lower_bound(&self) -> Option<usize> {
        self.diameter_lower_bound
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

#[derive(Debug, Clone)]
struct HierarchyGroup {
    block_id: String,
    node_ids: Vec<NodeId>,
    parent_block_id: Option<String>,
    child_block_ids: Vec<String>,
    depth: usize,
    representatives: Vec<TopologyRepresentative>,
}

impl HierarchyGroup {
    fn into_group(self) -> TopologyGroup {
        TopologyGroup {
            group_id: self.block_id,
            node_ids: self.node_ids,
            parent_group_id: self.parent_block_id,
            child_group_ids: self.child_block_ids,
            depth: self.depth,
            representatives: self.representatives,
        }
    }
}

fn build_hierarchy(
    node_ids: &[NodeId],
    config: &BoundedTopologyConfig,
) -> Result<Vec<HierarchyGroup>, BoundedTopologyError> {
    if node_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut groups = Vec::new();
    build_hierarchy_group(
        node_ids.to_vec(),
        None,
        "group-root".to_string(),
        0,
        0,
        Vec::new(),
        config,
        &mut groups,
    )?;
    groups.sort_by(|left, right| {
        left.depth
            .cmp(&right.depth)
            .then_with(|| left.block_id.cmp(&right.block_id))
    });
    Ok(groups)
}

#[allow(clippy::too_many_arguments)]
fn build_hierarchy_group(
    mut node_ids: Vec<NodeId>,
    parent_block_id: Option<String>,
    block_id: String,
    depth: usize,
    hash_depth: usize,
    prefix: Vec<(usize, usize)>,
    config: &BoundedTopologyConfig,
    groups: &mut Vec<HierarchyGroup>,
) -> Result<(), BoundedTopologyError> {
    node_ids.sort();
    if node_ids.len() <= config.block_size {
        groups.push(HierarchyGroup {
            block_id,
            node_ids,
            parent_block_id,
            child_block_ids: Vec::new(),
            depth,
            representatives: Vec::new(),
        });
        return Ok(());
    }

    let mut split = None;
    for probe in hash_depth..hash_depth.saturating_add(MAX_HASH_PREFIX_PROBES) {
        let mut buckets = BTreeMap::<usize, Vec<NodeId>>::new();
        for node_id in &node_ids {
            buckets
                .entry(hash_prefix_digit(node_id, probe, config))
                .or_default()
                .push(node_id.clone());
        }
        if buckets.len() > 1 {
            split = Some((probe, buckets));
            break;
        }
    }
    let (split_depth, buckets) = split.ok_or(BoundedTopologyError::InvariantViolation {
        reason: "hash-prefix hierarchy could not split an oversized leaf",
    })?;

    let child_specs = buckets
        .into_iter()
        .map(|(digit, members)| {
            let mut child_prefix = prefix.clone();
            child_prefix.push((split_depth, digit));
            let child_id = hierarchy_group_id(&child_prefix, config);
            (digit, child_id, child_prefix, members)
        })
        .collect::<Vec<_>>();
    let child_block_ids = child_specs
        .iter()
        .map(|(_, child_id, _, _)| child_id.clone())
        .collect::<Vec<_>>();
    groups.push(HierarchyGroup {
        block_id: block_id.clone(),
        node_ids,
        parent_block_id,
        child_block_ids,
        depth,
        representatives: Vec::new(),
    });
    for (_, child_id, child_prefix, members) in child_specs {
        build_hierarchy_group(
            members,
            Some(block_id.clone()),
            child_id,
            depth + 1,
            split_depth + 1,
            child_prefix,
            config,
            groups,
        )?;
    }
    Ok(())
}

fn hash_prefix_digit(node_id: &NodeId, hash_depth: usize, config: &BoundedTopologyConfig) -> usize {
    let mut material = Vec::new();
    append_hash_field(&mut material, b"ipars-hierarchy-prefix");
    append_hash_field(&mut material, TOPOLOGY_ALGORITHM_VERSION.as_bytes());
    append_hash_field(&mut material, config.permutation_seed.as_bytes());
    append_hash_field(&mut material, hash_depth.to_string().as_bytes());
    append_hash_field(&mut material, node_id.as_str().as_bytes());
    cryptographic_hash_u64(&material) as usize % config.block_size
}

fn hierarchy_group_id(prefix: &[(usize, usize)], config: &BoundedTopologyConfig) -> String {
    let mut material = Vec::new();
    append_hash_field(&mut material, b"ipars-hierarchy-group");
    append_hash_field(&mut material, TOPOLOGY_ALGORITHM_VERSION.as_bytes());
    append_hash_field(&mut material, config.permutation_seed.as_bytes());
    for (depth, digit) in prefix {
        append_hash_field(&mut material, depth.to_string().as_bytes());
        append_hash_field(&mut material, digit.to_string().as_bytes());
    }
    format!("group-{:016x}", cryptographic_hash_u64(&material))
}

fn add_leaf_cycles(
    hierarchy: &[HierarchyGroup],
    adjacency: &mut BTreeMap<NodeId, BTreeSet<NodeId>>,
    edge_placements: &mut BTreeMap<TopologyEdge, BTreeSet<TopologyEdgePlacement>>,
) {
    for group in hierarchy
        .iter()
        .filter(|group| group.child_block_ids.is_empty())
    {
        add_placed_cycle(
            adjacency,
            edge_placements,
            &group.node_ids,
            TopologyEdgePlacement {
                level: group.depth,
                plane: 0,
                kind: TopologyEdgeKind::LeafCycle,
                group_id: group.block_id.clone(),
            },
        );
    }
}

fn allocate_representatives_and_hierarchy_edges(
    hierarchy: &mut [HierarchyGroup],
    config: &BoundedTopologyConfig,
    reserved_representative_degree: &mut BTreeMap<NodeId, usize>,
    adjacency: &mut BTreeMap<NodeId, BTreeSet<NodeId>>,
    edge_placements: &mut BTreeMap<TopologyEdge, BTreeSet<TopologyEdgePlacement>>,
) -> Result<(), BoundedTopologyError> {
    let index_by_id = hierarchy
        .iter()
        .enumerate()
        .map(|(index, group)| (group.block_id.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let mut group_order = hierarchy
        .iter()
        .enumerate()
        .filter(|(_, group)| group.parent_block_id.is_some())
        .map(|(index, group)| (group.depth, group.block_id.clone(), index))
        .collect::<Vec<_>>();
    group_order.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

    for (_, _, group_index) in group_order {
        let role_degree = 1;
        let candidates = hierarchy[group_index].node_ids.clone();
        let representatives = select_group_representatives(
            &hierarchy[group_index].block_id,
            &candidates,
            role_degree,
            reserved_representative_degree,
            adjacency,
            config,
        )?;
        for representative in &representatives {
            *reserved_representative_degree
                .entry(representative.node_id.clone())
                .or_default() += role_degree;
        }
        hierarchy[group_index].representatives = representatives;
    }

    let parent_ids = hierarchy
        .iter()
        .filter(|group| group.child_block_ids.len() >= 2)
        .map(|group| group.block_id.clone())
        .collect::<Vec<_>>();
    for parent_id in parent_ids {
        let parent_index = index_by_id[&parent_id];
        let parent_depth = hierarchy[parent_index].depth;
        let child_ids = hierarchy[parent_index].child_block_ids.clone();
        add_hierarchy_block_ring(
            hierarchy,
            &index_by_id,
            &child_ids,
            adjacency,
            edge_placements,
            TopologyEdgePlacement {
                level: parent_depth,
                plane: 0,
                kind: TopologyEdgeKind::HierarchyLink,
                group_id: parent_id,
            },
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_hierarchy_block_ring(
    hierarchy: &[HierarchyGroup],
    index_by_id: &BTreeMap<String, usize>,
    child_ids: &[String],
    adjacency: &mut BTreeMap<NodeId, BTreeSet<NodeId>>,
    edge_placements: &mut BTreeMap<TopologyEdge, BTreeSet<TopologyEdgePlacement>>,
    placement: TopologyEdgePlacement,
) -> Result<(), BoundedTopologyError> {
    for index in 0..child_ids.len() {
        let source_child = &hierarchy[index_by_id[&child_ids[index]]];
        let target_child = &hierarchy[index_by_id[&child_ids[(index + 1) % child_ids.len()]]];
        let source = representative_for_plane(source_child, 1)?;
        let target = representative_for_plane(target_child, 0)?;
        add_undirected_edge(adjacency, source, target);
        if let Some(edge) = TopologyEdge::new(source.clone(), target.clone()) {
            edge_placements
                .entry(edge)
                .or_default()
                .insert(placement.clone());
        }
    }
    Ok(())
}

fn representative_for_plane(
    group: &HierarchyGroup,
    plane: usize,
) -> Result<&NodeId, BoundedTopologyError> {
    group
        .representatives
        .iter()
        .find(|representative| representative.plane == plane)
        .map(|representative| &representative.node_id)
        .ok_or_else(|| BoundedTopologyError::RepresentativeCapacity {
            group_id: group.block_id.clone(),
        })
}

fn select_group_representatives(
    group_id: &str,
    candidates: &[NodeId],
    role_degree: usize,
    reserved_representative_degree: &BTreeMap<NodeId, usize>,
    adjacency: &BTreeMap<NodeId, BTreeSet<NodeId>>,
    config: &BoundedTopologyConfig,
) -> Result<Vec<TopologyRepresentative>, BoundedTopologyError> {
    if candidates.len() == 1 {
        let node_id = candidates[0].clone();
        let degree = adjacency.get(&node_id).map(BTreeSet::len).unwrap_or(0);
        let reserved_degree = reserved_representative_degree
            .get(&node_id)
            .copied()
            .unwrap_or(0);
        if degree + reserved_degree + 2 * role_degree > config.max_degree {
            return Err(BoundedTopologyError::RepresentativeCapacity {
                group_id: group_id.to_string(),
            });
        }
        return Ok(vec![
            TopologyRepresentative {
                node_id: node_id.clone(),
                plane: 0,
            },
            TopologyRepresentative { node_id, plane: 1 },
        ]);
    }

    let mut selected = Vec::with_capacity(2);
    for plane in 0..2 {
        let candidate = candidates
            .iter()
            .filter(|node_id| {
                !selected
                    .iter()
                    .any(|representative: &TopologyRepresentative| {
                        &representative.node_id == *node_id
                    })
            })
            .filter(|node_id| {
                adjacency.get(*node_id).map(BTreeSet::len).unwrap_or(0)
                    + reserved_representative_degree
                        .get(*node_id)
                        .copied()
                        .unwrap_or(0)
                    + role_degree
                    <= config.max_degree
            })
            .max_by_key(|node_id| {
                (
                    representative_score(group_id, plane, node_id, config),
                    (*node_id).clone(),
                )
            })
            .cloned()
            .ok_or_else(|| BoundedTopologyError::RepresentativeCapacity {
                group_id: group_id.to_string(),
            })?;
        selected.push(TopologyRepresentative {
            node_id: candidate,
            plane,
        });
    }
    Ok(selected)
}

fn representative_score(
    group_id: &str,
    plane: usize,
    node_id: &NodeId,
    config: &BoundedTopologyConfig,
) -> u64 {
    let mut material = Vec::new();
    append_hash_field(&mut material, b"ipars-hierarchy-representative");
    append_hash_field(&mut material, TOPOLOGY_ALGORITHM_VERSION.as_bytes());
    append_hash_field(&mut material, config.permutation_seed.as_bytes());
    append_hash_field(&mut material, group_id.as_bytes());
    append_hash_field(&mut material, plane.to_string().as_bytes());
    append_hash_field(&mut material, node_id.as_str().as_bytes());
    cryptographic_hash_u64(&material)
}

fn add_placed_cycle(
    adjacency: &mut BTreeMap<NodeId, BTreeSet<NodeId>>,
    edge_placements: &mut BTreeMap<TopologyEdge, BTreeSet<TopologyEdgePlacement>>,
    cycle: &[NodeId],
    placement: TopologyEdgePlacement,
) {
    if cycle.len() < 2 {
        return;
    }
    let edge_count = if cycle.len() == 2 { 1 } else { cycle.len() };
    for index in 0..edge_count {
        let first = &cycle[index];
        let second = &cycle[(index + 1) % cycle.len()];
        add_undirected_edge(adjacency, first, second);
        if let Some(edge) = TopologyEdge::new(first.clone(), second.clone()) {
            edge_placements
                .entry(edge)
                .or_default()
                .insert(placement.clone());
        }
    }
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

fn calculate_diameter_lower_bound(adjacency: &BTreeMap<NodeId, BTreeSet<NodeId>>) -> Option<usize> {
    let mut source = adjacency.keys().next()?.clone();
    let mut lower_bound = 0;
    for _ in 0..4 {
        let distances = distances_from(&source, adjacency);
        if distances.len() != adjacency.len() {
            return None;
        }
        let (farthest, distance) = distances.iter().max_by(
            |(left_node, left_distance), (right_node, right_distance)| {
                left_distance
                    .cmp(right_distance)
                    .then_with(|| left_node.cmp(right_node))
            },
        )?;
        if *distance <= lower_bound {
            break;
        }
        lower_bound = *distance;
        source = farthest.clone();
    }
    Some(lower_bound)
}

fn graph_has_no_articulation_points(adjacency: &BTreeMap<NodeId, BTreeSet<NodeId>>) -> bool {
    if adjacency.len() <= 2 {
        return true;
    }
    let Some(root) = adjacency.keys().next().cloned() else {
        return true;
    };
    let mut discovery = BTreeMap::new();
    let mut low = BTreeMap::new();
    let mut time = 0;
    if articulation_dfs(&root, None, adjacency, &mut discovery, &mut low, &mut time) {
        return false;
    }
    discovery.len() == adjacency.len()
}

fn articulation_dfs(
    node: &NodeId,
    parent: Option<&NodeId>,
    adjacency: &BTreeMap<NodeId, BTreeSet<NodeId>>,
    discovery: &mut BTreeMap<NodeId, usize>,
    low: &mut BTreeMap<NodeId, usize>,
    time: &mut usize,
) -> bool {
    let discovered_at = *time;
    *time += 1;
    discovery.insert(node.clone(), discovered_at);
    low.insert(node.clone(), discovered_at);
    let mut child_count = 0;

    let Some(neighbors) = adjacency.get(node) else {
        return false;
    };
    for neighbor in neighbors {
        if parent == Some(neighbor) {
            continue;
        }
        if let Some(neighbor_discovery) = discovery.get(neighbor).copied() {
            if let Some(node_low) = low.get_mut(node) {
                *node_low = (*node_low).min(neighbor_discovery);
            }
            continue;
        }

        child_count += 1;
        if articulation_dfs(neighbor, Some(node), adjacency, discovery, low, time) {
            return true;
        }
        let neighbor_low = low.get(neighbor).copied().unwrap_or(discovered_at);
        if parent.is_some() && neighbor_low >= discovered_at {
            return true;
        }
        if let Some(node_low) = low.get_mut(node) {
            *node_low = (*node_low).min(neighbor_low);
        }
    }

    parent.is_none() && child_count > 1
}

#[cfg(test)]
fn graph_survives_any_single_node_failure(adjacency: &BTreeMap<NodeId, BTreeSet<NodeId>>) -> bool {
    if adjacency.len() <= 2 {
        return true;
    }
    adjacency.keys().all(|failed| {
        let Some(start) = adjacency.keys().find(|node_id| *node_id != failed) else {
            return true;
        };
        distances_from_avoiding(start, failed, adjacency).len() == adjacency.len() - 1
    })
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

#[cfg(test)]
fn distances_from_avoiding(
    source: &NodeId,
    unavailable: &NodeId,
    adjacency: &BTreeMap<NodeId, BTreeSet<NodeId>>,
) -> BTreeMap<NodeId, usize> {
    if source == unavailable || !adjacency.contains_key(source) {
        return BTreeMap::new();
    }
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
            if neighbor == unavailable || distances.contains_key(neighbor) {
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

fn index_path(path: &[NodeId], node_indexes: &BTreeMap<NodeId, usize>) -> Option<Box<[usize]>> {
    path.iter()
        .map(|node_id| node_indexes.get(node_id).copied())
        .collect::<Option<Vec<_>>>()
        .map(Vec::into_boxed_slice)
}

fn materialize_indexed_path(path: &[usize], node_ids: &[NodeId]) -> Option<Vec<NodeId>> {
    path.iter()
        .map(|index| node_ids.get(*index).cloned())
        .collect()
}

fn reconstruct_indexed_path(
    source_index: usize,
    destination_index: usize,
    predecessors: &[Option<usize>],
) -> Option<Vec<usize>> {
    let mut reversed = vec![destination_index];
    let mut cursor = destination_index;
    while cursor != source_index {
        cursor = predecessors.get(cursor).copied().flatten()?;
        reversed.push(cursor);
    }
    reversed.reverse();
    Some(reversed)
}

#[derive(Debug, Clone)]
struct ResidualEdge {
    to: usize,
    reverse_index: usize,
    capacity: u8,
    initial_capacity: u8,
}

fn add_residual_edge(graph: &mut [Vec<ResidualEdge>], from: usize, to: usize, capacity: u8) {
    let forward_reverse_index = graph[to].len();
    let reverse_reverse_index = graph[from].len();
    graph[from].push(ResidualEdge {
        to,
        reverse_index: forward_reverse_index,
        capacity,
        initial_capacity: capacity,
    });
    graph[to].push(ResidualEdge {
        to: from,
        reverse_index: reverse_reverse_index,
        capacity: 0,
        initial_capacity: 0,
    });
}

fn augment_unit_flow(graph: &mut [Vec<ResidualEdge>], source: usize, sink: usize) -> bool {
    let mut predecessor = vec![None; graph.len()];
    let mut queue = VecDeque::from([source]);
    predecessor[source] = Some((source, usize::MAX));

    while let Some(current) = queue.pop_front() {
        for (edge_index, edge) in graph[current].iter().enumerate() {
            if edge.capacity == 0 || predecessor[edge.to].is_some() {
                continue;
            }
            predecessor[edge.to] = Some((current, edge_index));
            if edge.to == sink {
                break;
            }
            queue.push_back(edge.to);
        }
        if predecessor[sink].is_some() {
            break;
        }
    }
    if predecessor[sink].is_none() {
        return false;
    }

    let mut cursor = sink;
    while cursor != source {
        let Some((previous, edge_index)) = predecessor[cursor] else {
            return false;
        };
        let reverse_index = graph[previous][edge_index].reverse_index;
        graph[previous][edge_index].capacity -= 1;
        graph[cursor][reverse_index].capacity += 1;
        cursor = previous;
    }
    true
}

fn extract_flow_path(
    graph: &[Vec<ResidualEdge>],
    remaining_flow: &mut [Vec<u8>],
    source: usize,
    sink: usize,
) -> Option<Vec<usize>> {
    let mut predecessor = vec![None; graph.len()];
    let mut queue = VecDeque::from([source]);
    predecessor[source] = Some((source, usize::MAX));

    while let Some(current) = queue.pop_front() {
        for (edge_index, edge) in graph[current].iter().enumerate() {
            if remaining_flow[current][edge_index] == 0 || predecessor[edge.to].is_some() {
                continue;
            }
            predecessor[edge.to] = Some((current, edge_index));
            if edge.to == sink {
                break;
            }
            queue.push_back(edge.to);
        }
        if predecessor[sink].is_some() {
            break;
        }
    }
    predecessor[sink]?;

    let mut reversed = vec![sink];
    let mut cursor = sink;
    while cursor != source {
        let (previous, edge_index) = predecessor[cursor]?;
        remaining_flow[previous][edge_index] -= 1;
        reversed.push(previous);
        cursor = previous;
    }
    reversed.reverse();
    Some(reversed)
}

fn two_internally_vertex_disjoint_paths(
    adjacency: &BTreeMap<NodeId, BTreeSet<NodeId>>,
    source: &NodeId,
    destination: &NodeId,
) -> Option<(Vec<NodeId>, Vec<NodeId>)> {
    if source == destination || adjacency.len() < 3 {
        return None;
    }
    let node_ids = adjacency.keys().cloned().collect::<Vec<_>>();
    let indexes = node_ids
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, node_id)| (node_id, index))
        .collect::<BTreeMap<_, _>>();
    let source_index = *indexes.get(source)?;
    let destination_index = *indexes.get(destination)?;
    let in_index = |index: usize| index * 2;
    let out_index = |index: usize| index * 2 + 1;
    let mut graph = vec![Vec::new(); node_ids.len() * 2];

    for index in 0..node_ids.len() {
        if index != source_index && index != destination_index {
            add_residual_edge(&mut graph, in_index(index), out_index(index), 1);
        }
    }
    for (node_id, neighbors) in adjacency {
        let from_index = *indexes.get(node_id)?;
        if from_index == destination_index {
            continue;
        }
        for neighbor in neighbors {
            let to_index = *indexes.get(neighbor)?;
            if to_index == source_index {
                continue;
            }
            add_residual_edge(&mut graph, out_index(from_index), in_index(to_index), 1);
        }
    }

    let flow_source = out_index(source_index);
    let flow_sink = in_index(destination_index);
    if !augment_unit_flow(&mut graph, flow_source, flow_sink)
        || !augment_unit_flow(&mut graph, flow_source, flow_sink)
    {
        return None;
    }

    let mut remaining_flow = graph
        .iter()
        .map(|edges| {
            edges
                .iter()
                .map(|edge| edge.initial_capacity.saturating_sub(edge.capacity))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut paths = Vec::with_capacity(2);
    for _ in 0..2 {
        let flow_path = extract_flow_path(&graph, &mut remaining_flow, flow_source, flow_sink)?;
        let mut node_path = vec![source.clone()];
        for network_edge in flow_path.windows(2) {
            if network_edge[0] % 2 == 1 && network_edge[1] % 2 == 0 {
                node_path.push(node_ids[network_edge[1] / 2].clone());
            }
        }
        if node_path.last() != Some(destination) {
            return None;
        }
        paths.push(node_path);
    }
    paths.sort_by(|left, right| left.len().cmp(&right.len()).then_with(|| left.cmp(right)));
    let secondary = paths.pop()?;
    let primary = paths.pop()?;
    Some((primary, secondary))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

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
        assert_eq!(topology.diameter_lower_bound(), Some(0));
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
        assert_eq!(topology.diameter_lower_bound(), Some(1));
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
    fn representative_capacity_uses_the_configured_degree_limit() {
        let candidates = [
            NodeId::from_string("candidate-a"),
            NodeId::from_string("candidate-b"),
        ];
        let adjacency = candidates
            .iter()
            .enumerate()
            .map(|(candidate_index, candidate)| {
                let neighbors = (0..4)
                    .map(|neighbor_index| {
                        NodeId::from_string(format!("neighbor-{candidate_index}-{neighbor_index}"))
                    })
                    .collect();
                (candidate.clone(), neighbors)
            })
            .collect::<BTreeMap<_, BTreeSet<_>>>();
        let reserved_degree = BTreeMap::new();
        let degree_four = BoundedTopologyConfig::new(4);
        let degree_six = BoundedTopologyConfig::new(6);

        for candidate_count in [1, 2] {
            let candidates = &candidates[..candidate_count];
            assert!(matches!(
                select_group_representatives(
                    "capacity-test",
                    candidates,
                    1,
                    &reserved_degree,
                    &adjacency,
                    &degree_four,
                ),
                Err(BoundedTopologyError::RepresentativeCapacity { .. })
            ));

            let representatives = match select_group_representatives(
                "capacity-test",
                candidates,
                1,
                &reserved_degree,
                &adjacency,
                &degree_six,
            ) {
                Ok(representatives) => representatives,
                Err(error) => panic!(
                    "degree six must admit representatives with four existing links: {error}"
                ),
            };
            assert_eq!(representatives.len(), 2);
            assert_eq!(
                representatives
                    .iter()
                    .map(TopologyRepresentative::plane)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([0, 1])
            );
            assert_eq!(
                representatives[0].node_id() == representatives[1].node_id(),
                candidate_count == 1
            );
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
    fn recursive_groups_partition_membership_and_expose_placements() {
        let nodes = records(64);
        let topology = topology_with_config(
            &nodes,
            &BoundedTopologyConfig::new(4)
                .with_block_size(4)
                .with_permutation_seed("cluster-a"),
        );

        assert_eq!(topology.fanout(), 4);
        let leaf_groups = topology
            .groups()
            .iter()
            .filter(|group| group.is_leaf())
            .collect::<Vec<_>>();
        assert!(leaf_groups
            .iter()
            .all(|block| block.is_leaf() && block.node_ids().len() <= 4));
        let members = leaf_groups
            .iter()
            .flat_map(|block| block.node_ids().iter().cloned())
            .collect::<BTreeSet<_>>();
        assert_eq!(members.len(), nodes.len());
        assert_eq!(
            leaf_groups
                .iter()
                .map(|block| block.node_ids().len())
                .sum::<usize>(),
            nodes.len()
        );

        let groups_by_id = topology
            .groups()
            .iter()
            .map(|group| (group.group_id().to_string(), group))
            .collect::<BTreeMap<_, _>>();
        let root = groups_by_id["group-root"];
        assert_eq!(root.depth(), 0);
        assert_eq!(root.parent_group_id(), None);
        for group in topology.groups() {
            assert!(group.child_group_ids().len() <= 4);
            if let Some(parent_id) = group.parent_group_id() {
                let parent = groups_by_id[parent_id];
                assert_eq!(group.depth(), parent.depth() + 1);
                assert!(parent
                    .child_group_ids()
                    .contains(&group.group_id().to_string()));
                assert_eq!(group.representatives().len(), 2);
            }
        }
        assert!(topology.edge_placements().values().any(|placements| {
            placements
                .iter()
                .any(|placement| placement.kind() == TopologyEdgeKind::HierarchyLink)
        }));
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
        assert_ne!(
            small_blocks.edge_placements(),
            large_blocks.edge_placements()
        );
        assert!(
            small_blocks
                .groups()
                .iter()
                .filter(|group| group.is_leaf())
                .count()
                > large_blocks
                    .groups()
                    .iter()
                    .filter(|group| group.is_leaf())
                    .count()
        );
        assert!(small_blocks.invariants().are_satisfied());
        assert!(large_blocks.invariants().are_satisfied());
    }

    #[test]
    fn every_supported_policy_is_deterministic_bounded_and_locally_reassigned_at_one_thousand_nodes(
    ) {
        let nodes = records(1_000);
        let reordered = nodes.iter().cloned().rev().collect::<Vec<_>>();
        let cases = SUPPORTED_MAX_DEGREES
            .into_iter()
            .flat_map(|max_degree| {
                (usize::from(MIN_OVERLAY_BLOCK_SIZE)..=usize::from(MAX_OVERLAY_BLOCK_SIZE))
                    .map(move |block_size| (max_degree, block_size))
            })
            .collect::<Vec<_>>();
        let maximum_representative_changes = AtomicUsize::new(0);
        let worker_count = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(8)
            .min(cases.len());
        let chunk_size = cases.len().div_ceil(worker_count);

        std::thread::scope(|scope| {
            for chunk in cases.chunks(chunk_size) {
                let nodes = &nodes;
                let reordered = &reordered;
                let maximum_representative_changes = &maximum_representative_changes;
                scope.spawn(move || {
                    for &(max_degree, block_size) in chunk {
                        let config = BoundedTopologyConfig::new(max_degree)
                            .with_block_size(block_size)
                            .with_permutation_seed("all-supported-policies");
                        let initial = topology_with_config(nodes, &config);
                        let reordered_topology = topology_with_config(reordered, &config);
                        assert!(
                            initial == reordered_topology,
                            "N=1000, D={max_degree}, B={block_size} depends on input order"
                        );
                        assert_degree_bound(&initial, max_degree, block_size);
                        drop(reordered_topology);

                        let removed_node = busiest_representative(&initial);
                        let survivors = nodes
                            .iter()
                            .filter(|node| node.node_id != removed_node)
                            .cloned()
                            .collect::<Vec<_>>();
                        let updated = topology_with_config(&survivors, &config);
                        assert_degree_bound(&updated, max_degree, block_size);
                        assert_stable_groups_keep_representatives(
                            &initial,
                            &updated,
                            &removed_node,
                            max_degree,
                            block_size,
                        );

                        let affected_group_count = initial
                            .groups()
                            .iter()
                            .filter(|group| group.node_ids().contains(&removed_node))
                            .count();
                        let representative_changes =
                            changed_representative_slots(&initial, &updated);
                        let representative_change_bound = 4 * (block_size + affected_group_count);
                        assert!(
                            representative_changes <= representative_change_bound,
                            "N=1000, D={max_degree}, B={block_size}: deleting \
                             {removed_node} changed {representative_changes} representative slots \
                             (bound {representative_change_bound}, affected hierarchy groups \
                             {affected_group_count})"
                        );
                        assert!(updated.groups().iter().all(|group| {
                            group
                                .representatives()
                                .iter()
                                .all(|representative| representative.node_id() != &removed_node)
                        }));
                        maximum_representative_changes
                            .fetch_max(representative_changes, Ordering::Relaxed);
                    }
                });
            }
        });

        eprintln!(
            "all {} supported policies passed; maximum representative slot changes after one deletion: {}",
            cases.len(),
            maximum_representative_changes.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn thousand_node_paths_fit_the_wire_path_limit_for_every_supported_fanout() {
        let nodes = records(1_000);
        let mut maximum_diameter = 0;
        for block_size in [4, 8, 16, 32, 64] {
            let topology = topology_with_config(
                &nodes,
                &BoundedTopologyConfig::new(4)
                    .with_block_size(block_size)
                    .with_permutation_seed("cluster-a"),
            );
            let diameter = exact_indexed_diameter(&topology);
            maximum_diameter = maximum_diameter.max(diameter);
            eprintln!("fanout {block_size}: exact diameter {diameter}");
        }
        assert!(
            maximum_diameter < ipars_types::MAX_OVERLAY_PATH_NODES,
            "diameter {maximum_diameter} exceeds the overlay wire path limit"
        );
        assert!(
            maximum_diameter.saturating_sub(1)
                <= ipars_types::MAX_OVERLAY_PATH_NODES.saturating_sub(2),
            "diameter {maximum_diameter} exceeds the multihop intermediate-node limit"
        );
    }

    #[test]
    fn thousand_node_sampled_disjoint_paths_fit_the_wire_path_limit() {
        let nodes = records(1_000);
        let sampled_sources = [0, 199, 398, 597, 796, 995];
        let sampled_destinations = [0, 111, 222, 333, 444, 555, 666, 777, 888, 999];
        for block_size in [4, 8, 16, 32, 64] {
            let topology = topology_with_config(
                &nodes,
                &BoundedTopologyConfig::new(4)
                    .with_block_size(block_size)
                    .with_permutation_seed("cluster-a"),
            );
            let mut maximum_primary_nodes = 0;
            let mut maximum_secondary_nodes = 0;
            for source_index in sampled_sources {
                for destination_index in sampled_destinations {
                    if destination_index == source_index {
                        continue;
                    }
                    let destination = &nodes[destination_index];
                    let paths = topology
                        .paths(&nodes[source_index].node_id, &destination.node_id)
                        .unwrap_or_else(|| {
                            panic!(
                                "{} must reach {}",
                                nodes[source_index].node_id, destination.node_id
                            )
                        });
                    maximum_primary_nodes = maximum_primary_nodes.max(paths.primary.len());
                    let secondary = paths.secondary.unwrap_or_else(|| {
                        panic!(
                            "{} to {} must have a secondary path",
                            nodes[source_index].node_id, destination.node_id
                        )
                    });
                    maximum_secondary_nodes = maximum_secondary_nodes.max(secondary.nodes.len());
                }
            }
            eprintln!(
                "fanout {block_size}: sampled primary {maximum_primary_nodes}, secondary {maximum_secondary_nodes} nodes"
            );
            assert!(
                maximum_primary_nodes <= ipars_types::MAX_OVERLAY_PATH_NODES,
                "fanout {block_size} primary path has {maximum_primary_nodes} nodes"
            );
            assert!(
                maximum_secondary_nodes <= ipars_types::MAX_OVERLAY_PATH_NODES,
                "fanout {block_size} secondary path has {maximum_secondary_nodes} nodes"
            );
            assert!(
                maximum_secondary_nodes.saturating_sub(2)
                    <= ipars_types::MAX_OVERLAY_PATH_NODES.saturating_sub(2),
                "fanout {block_size} secondary relay path has too many nodes"
            );
        }
    }

    #[test]
    fn capacity_scan_covers_all_node_counts_and_fanout_boundaries() {
        let mut cases = BTreeSet::new();
        for node_count in 5..=256 {
            for block_size in [4, 5, 8, 16, 32, 64] {
                cases.insert((node_count, block_size));
            }
        }
        for block_size in 4..=64 {
            for node_count in [
                5,
                block_size,
                block_size + 1,
                2 * block_size - 1,
                2 * block_size,
                2 * block_size + 1,
                4 * block_size + 1,
            ] {
                cases.insert((node_count, block_size));
            }
        }
        let cases = cases.into_iter().collect::<Vec<_>>();
        let worker_count = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(8)
            .min(cases.len());
        let chunk_size = cases.len().div_ceil(worker_count);
        std::thread::scope(|scope| {
            for chunk in cases.chunks(chunk_size) {
                scope.spawn(move || {
                    for &(node_count, block_size) in chunk {
                        assert_capacity_case(node_count, block_size);
                    }
                });
            }
        });
    }

    #[test]
    fn one_thousand_nodes_survive_every_single_node_failure() {
        let topology = topology(&records(1_000), 4);
        assert!(graph_survives_any_single_node_failure(topology.adjacency()));
    }

    #[test]
    fn one_node_addition_changes_only_a_bounded_number_of_edges() {
        let initial = topology(&records(256), 4);
        let expanded = topology(&records(257), 4);
        let initial_edges = initial
            .edge_placements()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let expanded_edges = expanded
            .edge_placements()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let changed_edges = initial_edges.symmetric_difference(&expanded_edges).count();

        assert!(
            changed_edges <= 64,
            "one join changed {changed_edges} physical edges"
        );
    }

    #[test]
    fn one_thousand_nodes_have_bounded_degree_hierarchy_and_cached_diameter_bound() {
        let nodes = records(1_000);
        for max_degree in SUPPORTED_MAX_DEGREES {
            let started = Instant::now();
            let topology = topology(&nodes, max_degree);
            let synthesis_elapsed = started.elapsed();
            assert!(topology.invariants().are_satisfied());
            assert_eq!(topology.invariants().node_count, 1_000);
            assert!(topology.invariants().max_observed_degree <= max_degree);
            assert!(topology.groups().iter().all(|group| {
                group.child_group_ids().len() <= topology.fanout()
                    && (group.parent_group_id().is_none()
                        || group.depth() > 0 && group.representatives().len() == 2)
            }));
            let max_depth = topology
                .groups()
                .iter()
                .map(TopologyGroup::depth)
                .max()
                .unwrap_or(0);
            let diameter_lower_bound = topology.diameter_lower_bound().unwrap_or(0);
            assert!(max_depth > 1);
            assert!(topology.groups().len() < nodes.len());
            assert!(topology.invariants().edge_count <= nodes.len() * 2);
            eprintln!(
                "degree {max_degree}: {} groups, {} levels, {} edges, diameter >= {diameter_lower_bound}, synthesized in {synthesis_elapsed:?}",
                topology.groups().len(),
                max_depth + 1,
                topology.invariants().edge_count
            );

            let cached_started = Instant::now();
            for _ in 0..10_000 {
                std::hint::black_box(topology.diameter_lower_bound());
            }
            assert!(
                cached_started.elapsed()
                    < synthesis_elapsed.max(std::time::Duration::from_millis(1))
            );
        }
    }

    #[test]
    fn bounded_next_hop_table_uses_distinct_source_neighbors_at_one_thousand_nodes() {
        let nodes = records(1_000);
        for max_degree in SUPPORTED_MAX_DEGREES {
            let topology = topology(&nodes, max_degree);
            let source = &nodes[17].node_id;
            let Some(neighbors) = topology.neighbors(source) else {
                panic!("source must be present in synthesized topology");
            };
            assert_eq!(topology.cached_next_hop_source_count(), 0);
            let started = Instant::now();
            let Some(next_hops) = topology.next_hops_from(source) else {
                panic!("source must have a next-hop table");
            };
            let table_elapsed = started.elapsed();

            assert_eq!(next_hops.len(), nodes.len() - 1);
            for destination in topology.adjacency().keys().filter(|node| *node != source) {
                let Some((primary, secondary)) = next_hops.get(destination) else {
                    panic!("every remote node must have next hops");
                };
                assert!(neighbors.contains(primary));
                let Some(secondary) = secondary.as_ref() else {
                    panic!("next-hop table must retain the alternate first hop");
                };
                assert!(neighbors.contains(secondary));
                assert_ne!(secondary, primary);
            }
            assert_eq!(topology.cached_next_hop_source_count(), 1);
            assert_eq!(topology.next_hops_from(source), Some(next_hops.clone()));
            assert_eq!(topology.cached_next_hop_source_count(), 1);
            eprintln!(
                "degree {max_degree}: built {} destinations in {:?}, verified in {:?}",
                next_hops.len(),
                table_elapsed,
                started.elapsed()
            );
        }
    }

    #[test]
    fn thousand_node_same_source_queries_build_only_requested_pairs() {
        let nodes = records(1_000);
        let topology = Arc::new(topology(&nodes, 4));
        let source = Arc::new(nodes[17].node_id.clone());
        let sampled_destinations = [999, 111, 444, 777]
            .into_iter()
            .map(|destination_index| {
                (
                    destination_index,
                    topology
                        .uncached_paths(source.as_ref(), &nodes[destination_index].node_id)
                        .unwrap_or_else(|| {
                            panic!(
                                "{} must reach {}",
                                source.as_ref(),
                                nodes[destination_index].node_id
                            )
                        }),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(topology.path_cache_slot_count(), nodes.len());
        assert_eq!(topology.cached_path_source_count(), 0);
        assert_eq!(topology.path_cache_build_count(), 0);
        assert_eq!(topology.path_cache_pair_build_count(), 0);
        assert_eq!(topology.cached_path_destination_count(source.as_ref()), 0);

        let worker_count = 32;
        let barrier = Arc::new(Barrier::new(worker_count));
        let first_destination_index = sampled_destinations[0].0;
        let first_lookup_started = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..worker_count {
                let topology = Arc::clone(&topology);
                let source = Arc::clone(&source);
                let barrier = Arc::clone(&barrier);
                let nodes = &nodes;
                scope.spawn(move || {
                    barrier.wait();
                    let destination = &nodes[first_destination_index].node_id;
                    let paths = topology
                        .paths(source.as_ref(), destination)
                        .unwrap_or_else(|| {
                            panic!(
                                "{} must reach {destination} through the cached topology",
                                source.as_ref()
                            )
                        });
                    assert_eq!(paths.primary.first(), Some(source.as_ref()));
                    assert_eq!(paths.primary.last(), Some(destination));
                });
            }
        });
        let first_lookup_elapsed = first_lookup_started.elapsed();

        assert_eq!(topology.cached_path_source_count(), 1);
        assert_eq!(topology.path_cache_build_count(), 1);
        assert_eq!(topology.path_cache_pair_build_count(), 1);
        assert_eq!(topology.cached_path_destination_count(source.as_ref()), 1);
        assert!(
            first_lookup_elapsed < Duration::from_secs(5),
            "one 1,000-node source/pair build took {first_lookup_elapsed:?}"
        );

        let additional_lookup_started = Instant::now();
        for (destination_index, expected) in &sampled_destinations {
            let actual = topology
                .paths(source.as_ref(), &nodes[*destination_index].node_id)
                .unwrap_or_else(|| {
                    panic!(
                        "{} must reach {}",
                        source.as_ref(),
                        nodes[*destination_index].node_id
                    )
                });
            assert_eq!(&actual, expected);
            let secondary = actual.secondary.as_ref().unwrap_or_else(|| {
                panic!(
                    "{} to {} must retain a secondary path",
                    source.as_ref(),
                    nodes[*destination_index].node_id
                )
            });
            assert_eq!(secondary.kind, SecondaryPathKind::VertexDisjoint);
            let primary_internal = actual
                .primary
                .iter()
                .skip(1)
                .take(actual.primary.len().saturating_sub(2))
                .collect::<BTreeSet<_>>();
            let secondary_internal = secondary
                .nodes
                .iter()
                .skip(1)
                .take(secondary.nodes.len().saturating_sub(2))
                .collect::<BTreeSet<_>>();
            assert!(primary_internal.is_disjoint(&secondary_internal));
        }
        let additional_lookup_elapsed = additional_lookup_started.elapsed();
        assert!(
            additional_lookup_elapsed < Duration::from_secs(5),
            "four 1,000-node source/pair lookups took {additional_lookup_elapsed:?}"
        );
        assert_eq!(
            topology.path_cache_pair_build_count(),
            sampled_destinations.len()
        );
        assert_eq!(
            topology.cached_path_destination_count(source.as_ref()),
            sampled_destinations.len()
        );

        for _ in 0..1_000 {
            for (destination_index, expected) in &sampled_destinations {
                assert_eq!(
                    topology.paths(source.as_ref(), &nodes[*destination_index].node_id),
                    Some(expected.clone())
                );
            }
        }
        assert_eq!(topology.path_cache_build_count(), 1);
        assert_eq!(
            topology.path_cache_pair_build_count(),
            sampled_destinations.len()
        );
        for (destination_index, expected) in sampled_destinations {
            assert_eq!(
                topology.paths(source.as_ref(), &nodes[destination_index].node_id),
                Some(expected)
            );
        }
    }

    #[test]
    fn alternate_next_hops_survive_primary_neighbor_failure_for_every_pair() {
        let nodes = records(64);
        let topology = topology(&nodes, 4);
        for source in &nodes {
            let next_hops = topology
                .next_hops_from(&source.node_id)
                .unwrap_or_else(|| panic!("{} must have a routing table", source.node_id));
            for destination in nodes
                .iter()
                .filter(|destination| destination.node_id != source.node_id)
            {
                let (primary, secondary) = next_hops
                    .get(&destination.node_id)
                    .unwrap_or_else(|| panic!("{} must have next hops", destination.node_id));
                let secondary = secondary.as_ref().unwrap_or_else(|| {
                    panic!(
                        "{} to {} must have an alternate first hop",
                        source.node_id, destination.node_id
                    )
                });
                let mut unavailable_nodes = BTreeSet::from([source.node_id.clone()]);
                if primary != &destination.node_id {
                    unavailable_nodes.insert(primary.clone());
                }
                let rerouted = topology.shortest_path_avoiding(
                    secondary,
                    &destination.node_id,
                    &unavailable_nodes,
                    &BTreeSet::new(),
                );
                assert!(
                    rerouted.is_some(),
                    "{} to {} cannot reroute from {} after {} fails",
                    source.node_id,
                    destination.node_id,
                    secondary,
                    primary
                );
            }
        }
        assert_eq!(topology.cached_next_hop_source_count(), nodes.len());
    }

    #[test]
    fn paths_avoiding_exclude_unavailable_nodes_from_both_routes() {
        let nodes = records(32);
        let topology = topology(&nodes, 4);
        let (source, destination, unavailable) = nodes
            .iter()
            .find_map(|source| {
                nodes.iter().find_map(|destination| {
                    if source.node_id == destination.node_id {
                        return None;
                    }
                    topology
                        .shortest_path(&source.node_id, &destination.node_id)
                        .and_then(|path| path.get(1).cloned())
                        .filter(|node_id| node_id != &destination.node_id)
                        .map(|unavailable| {
                            (
                                source.node_id.clone(),
                                destination.node_id.clone(),
                                unavailable,
                            )
                        })
                })
            })
            .unwrap_or_else(|| panic!("test topology must contain an internal transit node"));

        let paths = topology
            .paths_avoiding(
                &source,
                &destination,
                &BTreeSet::from([unavailable.clone()]),
            )
            .unwrap_or_else(|| {
                panic!("bounded topology must survive one unavailable transit node")
            });
        assert!(!paths.primary.contains(&unavailable));
        assert!(paths
            .secondary
            .as_ref()
            .is_none_or(|secondary| !secondary.nodes.contains(&unavailable)));
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
            panic!("two-connected hierarchy must provide an alternate route");
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
    fn every_node_pair_has_a_vertex_disjoint_secondary_path() {
        let nodes = records(64);
        let topology = topology(&nodes, 4);
        for (source_index, source) in nodes.iter().enumerate() {
            for destination in nodes.iter().skip(source_index + 1) {
                let expected = topology
                    .uncached_paths(&source.node_id, &destination.node_id)
                    .unwrap_or_else(|| {
                        panic!("{} must reach {}", source.node_id, destination.node_id)
                    });
                let paths = topology
                    .paths(&source.node_id, &destination.node_id)
                    .unwrap_or_else(|| {
                        panic!("{} must reach {}", source.node_id, destination.node_id)
                    });
                assert_eq!(
                    paths, expected,
                    "cached path selection changed for {} to {}",
                    source.node_id, destination.node_id
                );
                let secondary = paths.secondary.unwrap_or_else(|| {
                    panic!(
                        "{} to {} has no secondary path; primary={:?}",
                        source.node_id, destination.node_id, paths.primary
                    )
                });
                assert_eq!(secondary.kind, SecondaryPathKind::VertexDisjoint);
                let primary_internal = paths
                    .primary
                    .iter()
                    .skip(1)
                    .take(paths.primary.len().saturating_sub(2))
                    .collect::<BTreeSet<_>>();
                let secondary_internal = secondary
                    .nodes
                    .iter()
                    .skip(1)
                    .take(secondary.nodes.len().saturating_sub(2))
                    .collect::<BTreeSet<_>>();
                assert!(primary_internal.is_disjoint(&secondary_internal));
            }
        }
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
        for block_size in [1, 2, 3, 65] {
            assert_eq!(
                synthesize_bounded_topology(
                    &nodes,
                    &BoundedTopologyConfig::new(4).with_block_size(block_size)
                ),
                Err(BoundedTopologyError::InvalidBlockSize {
                    block_size,
                    minimum: 4,
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

    fn assert_degree_bound(topology: &BoundedTopology, max_degree: usize, block_size: usize) {
        assert!(
            topology.invariants().are_satisfied(),
            "N={}, D={max_degree}, B={block_size}: {:?}",
            topology.invariants().node_count,
            topology.invariants()
        );
        assert!(
            topology
                .adjacency()
                .values()
                .all(|neighbors| neighbors.len() <= max_degree),
            "N={}, D={max_degree}, B={block_size}: observed degree {}",
            topology.invariants().node_count,
            topology.invariants().max_observed_degree
        );
    }

    fn busiest_representative(topology: &BoundedTopology) -> NodeId {
        let mut assignments = BTreeMap::<NodeId, usize>::new();
        for representative in topology
            .groups()
            .iter()
            .flat_map(TopologyGroup::representatives)
        {
            *assignments
                .entry(representative.node_id().clone())
                .or_default() += 1;
        }
        let busiest = assignments
            .into_iter()
            .max_by_key(|(node_id, assignment_count)| (*assignment_count, node_id.clone()))
            .map(|(node_id, _)| node_id);
        match busiest {
            Some(node_id) => node_id,
            None => panic!("a 1,000-node hierarchy must have representatives"),
        }
    }

    fn assert_stable_groups_keep_representatives(
        initial: &BoundedTopology,
        updated: &BoundedTopology,
        removed_node: &NodeId,
        max_degree: usize,
        block_size: usize,
    ) {
        let updated_groups = updated
            .groups()
            .iter()
            .map(|group| (group.group_id(), group))
            .collect::<BTreeMap<_, _>>();
        for initial_group in initial.groups() {
            let Some(updated_group) = updated_groups.get(initial_group.group_id()) else {
                continue;
            };
            if initial_group.node_ids() == updated_group.node_ids() {
                assert!(
                    initial_group.representatives() == updated_group.representatives(),
                    "N=1000, D={max_degree}, B={block_size}: deleting {removed_node} \
                     changed representatives for unaffected group {}",
                    initial_group.group_id()
                );
            } else {
                assert!(
                    initial_group.node_ids().contains(removed_node),
                    "N=1000, D={max_degree}, B={block_size}: deleting {removed_node} \
                     changed membership outside its hierarchy path in group {}",
                    initial_group.group_id()
                );
            }
        }
    }

    fn changed_representative_slots(initial: &BoundedTopology, updated: &BoundedTopology) -> usize {
        let representative_assignments = |topology: &BoundedTopology| {
            topology
                .groups()
                .iter()
                .flat_map(|group| {
                    group.representatives().iter().map(|representative| {
                        (
                            (group.group_id().to_string(), representative.plane()),
                            representative.node_id().clone(),
                        )
                    })
                })
                .collect::<BTreeMap<_, _>>()
        };
        let initial_assignments = representative_assignments(initial);
        let updated_assignments = representative_assignments(updated);
        initial_assignments
            .keys()
            .chain(updated_assignments.keys())
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|slot| initial_assignments.get(slot) != updated_assignments.get(slot))
            .count()
    }

    fn assert_capacity_case(node_count: usize, block_size: usize) {
        let nodes = records(node_count);
        let node_ids = match canonical_node_ids(&nodes) {
            Ok(node_ids) => node_ids,
            Err(error) => panic!("generated IDs must be unique: {error}"),
        };
        let config = BoundedTopologyConfig::new(4)
            .with_block_size(block_size)
            .with_permutation_seed("capacity-scan");
        let mut hierarchy = match build_hierarchy(&node_ids, &config) {
            Ok(hierarchy) => hierarchy,
            Err(error) => {
                panic!("N={node_count}, B={block_size} hierarchy construction failed: {error}")
            }
        };
        let mut adjacency = node_ids
            .iter()
            .cloned()
            .map(|node_id| (node_id, BTreeSet::new()))
            .collect::<BTreeMap<_, _>>();
        let mut edge_placements = BTreeMap::new();
        let mut reserved_degree = BTreeMap::new();
        add_leaf_cycles(&hierarchy, &mut adjacency, &mut edge_placements);
        allocate_representatives_and_hierarchy_edges(
            &mut hierarchy,
            &config,
            &mut reserved_degree,
            &mut adjacency,
            &mut edge_placements,
        )
        .unwrap_or_else(|error| {
            panic!("N={node_count}, B={block_size} representative allocation failed: {error}")
        });
        let invariants = inspect_invariants(&adjacency, 4);
        assert!(
            invariants.are_satisfied(),
            "N={node_count}, B={block_size}: {invariants:?}"
        );
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

    fn exact_indexed_diameter(topology: &BoundedTopology) -> usize {
        let mut diameter = 0;
        for source in 0..topology.indexed_adjacency.len() {
            let mut distances = vec![usize::MAX; topology.indexed_adjacency.len()];
            distances[source] = 0;
            let mut queue = VecDeque::from([source]);
            while let Some(current) = queue.pop_front() {
                for &neighbor in &topology.indexed_adjacency[current] {
                    if distances[neighbor] != usize::MAX {
                        continue;
                    }
                    distances[neighbor] = distances[current] + 1;
                    diameter = diameter.max(distances[neighbor]);
                    queue.push_back(neighbor);
                }
            }
            assert!(distances.iter().all(|distance| *distance != usize::MAX));
        }
        diameter
    }
}
