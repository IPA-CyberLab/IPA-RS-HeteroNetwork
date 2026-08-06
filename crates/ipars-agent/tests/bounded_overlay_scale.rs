use std::collections::BTreeSet;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;
use ipars_agent::overlay_forwarder::{
    BoundedOverlayForwarder, OverlayForwardAction, OverlayForwarderConfig, OverlayForwarderError,
    OverlayPathSelection,
};
use ipars_types::{
    ClusterId, NeighborMap, NodeId, NodeRecord, OverlayNeighbor, OverlayNeighborKind, OverlayPath,
    Role, TokenPolicy, VpnIp,
};

const NODE_COUNT: usize = 1_000;
const REPRESENTATIVE_STRIDE: usize = 40;
const TOPOLOGY_EPOCH: u64 = 42;
const SOURCE_INDEX: usize = 0;
const DESTINATION_INDEX: usize = 500;

type TestResult = Result<(), Box<dyn Error>>;

fn node_id(index: usize) -> NodeId {
    NodeId::from_string(format!("scale-node-{index:04}"))
}

fn vpn_ip(index: usize) -> VpnIp {
    let base = u32::from(Ipv4Addr::new(10, 250, 0, 0));
    VpnIp(IpAddr::V4(Ipv4Addr::from(base + index as u32 + 1)))
}

fn node_record(index: usize) -> NodeRecord {
    NodeRecord {
        node_id: node_id(index),
        display_name: None,
        hostname: None,
        cluster_id: ClusterId::from_string("bounded-overlay-scale"),
        vpn_ip: vpn_ip(index),
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

fn neighbor_indices(index: usize) -> [(usize, OverlayNeighborKind); 4] {
    [
        (
            (index + REPRESENTATIVE_STRIDE) % NODE_COUNT,
            OverlayNeighborKind::BackbonePrimary,
        ),
        (
            (index + 1) % NODE_COUNT,
            OverlayNeighborKind::BackbonePrimary,
        ),
        (
            (index + NODE_COUNT - REPRESENTATIVE_STRIDE) % NODE_COUNT,
            OverlayNeighborKind::BackboneSecondary,
        ),
        (
            (index + NODE_COUNT - 1) % NODE_COUNT,
            OverlayNeighborKind::BackboneSecondary,
        ),
    ]
}

fn neighbor_map(index: usize, topology_epoch: u64) -> NeighborMap {
    NeighborMap {
        cluster_id: ClusterId::from_string("bounded-overlay-scale"),
        node_id: node_id(index),
        topology_epoch,
        routing_epoch: topology_epoch,
        max_degree: 4,
        on_demand_peer_limit: 4,
        vpn_cidr: "10.250.0.0/16"
            .parse()
            .unwrap_or_else(|error| panic!("static scale-test VPN CIDR must parse: {error}")),
        neighbors: neighbor_indices(index)
            .into_iter()
            .map(|(neighbor, kind)| OverlayNeighbor {
                node: node_record(neighbor),
                kind,
            })
            .collect(),
        aggregate_routes: Vec::new(),
        client_route_peers: Vec::new(),
        bootstrap_endpoints: Vec::new(),
        generated_at: Utc::now(),
    }
}

fn forwarder(index: usize) -> Result<BoundedOverlayForwarder, OverlayForwarderError> {
    BoundedOverlayForwarder::new(
        node_id(index),
        neighbor_map(index, TOPOLOGY_EPOCH),
        OverlayForwarderConfig::default(),
    )
}

fn primary_indices() -> Vec<usize> {
    let mut path = vec![SOURCE_INDEX];
    let mut current = SOURCE_INDEX;
    for _ in 0..12 {
        current = (current + REPRESENTATIVE_STRIDE) % NODE_COUNT;
        path.push(current);
    }
    for _ in 0..20 {
        current = (current + 1) % NODE_COUNT;
        path.push(current);
    }
    assert_eq!(current, DESTINATION_INDEX);
    path
}

fn secondary_indices() -> Vec<usize> {
    let mut path = vec![SOURCE_INDEX];
    let mut current = SOURCE_INDEX;
    for _ in 0..12 {
        current = (current + NODE_COUNT - REPRESENTATIVE_STRIDE) % NODE_COUNT;
        path.push(current);
    }
    for _ in 0..20 {
        current = (current + NODE_COUNT - 1) % NODE_COUNT;
        path.push(current);
    }
    assert_eq!(current, DESTINATION_INDEX);
    path
}

fn overlay_path(epoch: u64) -> OverlayPath {
    OverlayPath {
        topology_epoch: epoch,
        routing_epoch: epoch,
        source: node_id(SOURCE_INDEX),
        destination: vpn_ip(DESTINATION_INDEX).0,
        target: node_record(DESTINATION_INDEX),
        ordered_nodes: primary_indices().into_iter().map(node_id).collect(),
        secondary_ordered_nodes: Some(secondary_indices().into_iter().map(node_id).collect()),
        generated_at: Utc::now(),
    }
}

fn forwarded_datagram(
    action: OverlayForwardAction,
    expected_next_hop: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    match action {
        OverlayForwardAction::Forward { next_hop, datagram } => {
            assert_eq!(next_hop, node_id(expected_next_hop));
            Ok(datagram)
        }
        other => Err(format!("expected forwarding action, got {other:?}").into()),
    }
}

fn deliver_over_path(
    path: &OverlayPath,
    selection: OverlayPathSelection,
    path_indices: &[usize],
    payload: Vec<u8>,
) -> TestResult {
    let mut source = forwarder(SOURCE_INDEX)?;
    let mut action =
        source.encapsulate_selected(path, selection, [0x5a; 16], 1, payload.clone())?;
    let mut previous = SOURCE_INDEX;

    for &relay in &path_indices[1..path_indices.len() - 1] {
        let datagram = forwarded_datagram(action, relay)?;
        let mut relay_forwarder = forwarder(relay)?;
        action = relay_forwarder.receive(&node_id(previous), &datagram)?;
        previous = relay;
    }

    let datagram = forwarded_datagram(action, DESTINATION_INDEX)?;
    let mut destination = forwarder(DESTINATION_INDEX)?;
    assert_eq!(
        destination.receive(&node_id(previous), &datagram)?,
        OverlayForwardAction::Deliver {
            source: node_id(SOURCE_INDEX),
            payload,
        }
    );
    Ok(())
}

#[test]
fn thousand_nodes_keep_four_permanent_neighbors_and_linear_total_state() -> TestResult {
    let maps = (0..NODE_COUNT)
        .map(|index| neighbor_map(index, TOPOLOGY_EPOCH))
        .collect::<Vec<_>>();

    for map in &maps {
        map.validate()?;
        assert_eq!(map.max_degree, 4);
        assert_eq!(map.neighbors.len(), 4);
        assert!(map
            .neighbors
            .iter()
            .all(|neighbor| neighbor.node.node_id != map.node_id));
    }

    let total_permanent_neighbors = maps.iter().map(|map| map.neighbors.len()).sum::<usize>();
    assert_eq!(total_permanent_neighbors, NODE_COUNT * 4);
    assert!(total_permanent_neighbors < NODE_COUNT * (NODE_COUNT - 1));
    Ok(())
}

#[test]
fn distant_on_demand_path_delivers_over_multiple_hops() -> TestResult {
    let path = overlay_path(TOPOLOGY_EPOCH);
    let primary = primary_indices();
    let source_map = neighbor_map(SOURCE_INDEX, TOPOLOGY_EPOCH);

    assert!(primary.len() > 3);
    assert!(!source_map
        .neighbors
        .iter()
        .any(|neighbor| neighbor.node.node_id == node_id(DESTINATION_INDEX)));
    deliver_over_path(
        &path,
        OverlayPathSelection::Primary,
        &primary,
        b"opaque-inner-wireguard-datagram".to_vec(),
    )
}

#[test]
fn failed_primary_representative_edge_uses_disjoint_secondary_path() -> TestResult {
    let path = overlay_path(TOPOLOGY_EPOCH);
    let primary = primary_indices();
    let secondary = secondary_indices();
    let primary_edges = primary
        .windows(2)
        .map(|edge| (edge[0], edge[1]))
        .collect::<BTreeSet<_>>();
    let secondary_edges = secondary
        .windows(2)
        .map(|edge| (edge[0], edge[1]))
        .collect::<BTreeSet<_>>();

    assert!(primary_edges.is_disjoint(&secondary_edges));

    let mut source = forwarder(SOURCE_INDEX)?;
    let failed_primary = source.encapsulate(&path, [0x31; 16], 1, vec![1])?;
    assert!(matches!(
        failed_primary,
        OverlayForwardAction::Forward { next_hop, .. }
            if next_hop == node_id(REPRESENTATIVE_STRIDE)
    ));

    deliver_over_path(
        &path,
        OverlayPathSelection::Secondary,
        &secondary,
        b"secondary-after-primary-edge-failure".to_vec(),
    )
}

#[test]
fn stale_epoch_replay_and_on_demand_state_are_bounded() -> TestResult {
    let path = overlay_path(TOPOLOGY_EPOCH);
    let first_relay = REPRESENTATIVE_STRIDE;
    let mut source = forwarder(SOURCE_INDEX)?;
    let datagram = forwarded_datagram(
        source.encapsulate(&path, [0x41; 16], 7, vec![7])?,
        first_relay,
    )?;

    let mut newer_relay = BoundedOverlayForwarder::new(
        node_id(first_relay),
        neighbor_map(first_relay, TOPOLOGY_EPOCH + 1),
        OverlayForwarderConfig::default(),
    )?;
    assert_eq!(
        newer_relay.receive(&node_id(SOURCE_INDEX), &datagram),
        Err(OverlayForwarderError::StaleTopologyEpoch {
            current_epoch: TOPOLOGY_EPOCH + 1,
            received_epoch: TOPOLOGY_EPOCH,
        })
    );

    let config = OverlayForwarderConfig {
        replay_cache_capacity: 8,
        ..OverlayForwarderConfig::default()
    };
    let mut bounded_relay = BoundedOverlayForwarder::new(
        node_id(first_relay),
        neighbor_map(first_relay, TOPOLOGY_EPOCH),
        config,
    )?;
    let _ = bounded_relay.receive(&node_id(SOURCE_INDEX), &datagram)?;
    assert!(matches!(
        bounded_relay.receive(&node_id(SOURCE_INDEX), &datagram),
        Err(OverlayForwarderError::ReplayRejected {
            sequence: 7,
            highest: 7,
            ..
        })
    ));

    for path_number in 1_u8..=32 {
        let mut ephemeral_source = forwarder(SOURCE_INDEX)?;
        let next = forwarded_datagram(
            ephemeral_source.encapsulate(
                &path,
                [path_number; 16],
                u64::from(path_number) + 10,
                vec![path_number],
            )?,
            first_relay,
        )?;
        let _ = bounded_relay.receive(&node_id(SOURCE_INDEX), &next)?;
        assert!(bounded_relay.replay_cache_len() <= 8);
        assert_eq!(bounded_relay.neighbor_map().neighbors.len(), 4);
    }

    assert_eq!(bounded_relay.replay_cache_len(), 8);
    assert_eq!(bounded_relay.neighbor_map().neighbors.len(), 4);
    Ok(())
}
