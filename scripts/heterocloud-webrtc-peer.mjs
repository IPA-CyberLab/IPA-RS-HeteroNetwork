// Protocol adapted from sibling HeteroCloud-Flow/scripts/flow-e2e.mjs.
// Signaling, SDP, ICE credentials and candidate addresses stay in browser memory.
export function assertSignalingContext(credential, scope) {
  const reject = (code) => { throw Object.assign(new Error(code), { safeCode: code }); };
  const headers = Object.fromEntries(Object.entries(credential.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value]));
  let principal;
  try { principal = JSON.parse(Buffer.from(headers["x-flow-principal"], "base64url").toString("utf8")); }
  catch { reject("webrtc_preflight_invalid_principal_context"); }
  if (!Array.isArray(principal?.permissions) || !principal.permissions.includes("flow.signal.connect")) {
    reject("webrtc_preflight_missing_flow_signal_connect");
  }
  if (principal.organization_id !== scope.organization_id || principal.project_id !== scope.project_id ||
      principal.service_instance_id !== scope.service_instance_id || principal.context_id !== credential.context_id) {
    reject("webrtc_preflight_principal_scope_mismatch");
  }
  if (!Number.isFinite(principal.expires_at) || principal.expires_at * 1000 < Date.now() + 45000) {
    reject("webrtc_preflight_context_lifetime_too_short");
  }
  // This is an issuance regression guard, not client-side signature verification.
  // The server still authenticates the untouched signed headers over public WSS.
}

export async function connectFixturePeers(pageA, pageB, connections, headers, iceTransportPolicy) {
  const start = (page, connection, offerer) => page.evaluate(async (args) => {
    const { connection, headers, offerer, iceTransportPolicy } = args;
    const pc = new RTCPeerConnection({ iceServers: connection.ice.ice_servers, iceTransportPolicy });
    const socket = new WebSocket(connection.urls[0]);
    const outgoing = [];
    const incoming = [];
    let remote;
    let offered = false;
    let settled = false;
    let finishing = false;
    let resolve;
    let channel;
    let sent = 0;
    let received = 0;
    let stage = "signed_context_authentication";
    const result = new Promise((done) => { resolve = done; });
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      // Successful peers stay connected until the controller closes both pages.
      if (!value.passed) { socket.close(); pc.close(); }
      resolve(value);
    };
    const fail = (code) => finish({ passed: false, code, stage });
    const timer = setTimeout(() => fail("webrtc_timeout"), 35000);
    const send = (type, target, payload) => socket.send(JSON.stringify({ type, target, payload }));
    const offer = async () => {
      if (!offerer || offered || !remote) return;
      offered = true;
      const value = await pc.createOffer();
      await pc.setLocalDescription(value);
      send("offer", remote, { sdp: value.sdp });
    };
    const collect = async () => {
      if (finishing || settled) return;
      finishing = true;
      stage = "payload_get_stats";
      try {
        for (let attempt = 0; attempt < 30 && !settled; attempt++) {
          const stats = await pc.getStats();
          const values = [...stats.values()];
          const transport = values.find((item) => item.type === "transport" && item.selectedCandidatePairId);
          const pair = transport ? stats.get(transport.selectedCandidatePairId) :
            values.find((item) => item.type === "candidate-pair" && item.state === "succeeded" && (item.selected || item.nominated));
          const dc = values.find((item) => item.type === "data-channel" && item.label === "flow-e2e");
          if (pair && dc?.messagesSent >= 1 && dc.messagesReceived >= 1 && dc.bytesSent > 0 && dc.bytesReceived > 0) {
            const local = stats.get(pair.localCandidateId);
            const remoteCandidate = stats.get(pair.remoteCandidateId);
            const passed = sent === 1 && received === 1 && pair.state === "succeeded" &&
              pc.connectionState === "connected" &&
              (iceTransportPolicy !== "relay" || (local?.candidateType === "relay" && remoteCandidate?.candidateType === "relay"));
            finish({ passed, code: passed ? "payload_and_stats_verified" : "candidate_or_connection_check_failed",
              state: pc.connectionState, ice: pc.iceConnectionState,
              payload: { sent, received, exact_match: received === 1 },
              data_channel: { messages_sent: dc.messagesSent, messages_received: dc.messagesReceived,
                bytes_sent: dc.bytesSent, bytes_received: dc.bytesReceived },
              selected_candidate_pair: { state: pair.state, local_candidate_type: local?.candidateType,
                remote_candidate_type: remoteCandidate?.candidateType, bytes_sent: pair.bytesSent,
                bytes_received: pair.bytesReceived, current_round_trip_time: pair.currentRoundTripTime } });
            return;
          }
          await new Promise((done) => setTimeout(done, 100));
        }
        fail("payload_stats_missing");
      } catch { fail("stats_error"); }
    };
    const bind = (value) => {
      channel = value;
      channel.onerror = () => fail("data_channel_error");
      channel.onmessage = (event) => {
        if (event.data !== (offerer ? "flow-e2e-pong" : "flow-e2e-ping")) {
          fail("payload_mismatch");
          return;
        }
        received++;
        stage = "data_channel_payload";
        if (!offerer) { channel.send("flow-e2e-pong"); sent++; }
        // Give both peers time to sample their connected transport before closing.
        setTimeout(() => { void collect(); }, offerer ? 500 : 250);
      };
      if (offerer) channel.onopen = () => { channel.send("flow-e2e-ping"); sent++; };
    };
    pc.ondatachannel = (event) => bind(event.channel);
    if (offerer) bind(pc.createDataChannel("flow-e2e"));
    pc.onicecandidate = (event) => {
      if (!event.candidate || settled) return;
      const value = event.candidate.toJSON();
      try { if (remote) send("ice_candidate", remote, value); else outgoing.push(value); }
      catch { fail("candidate_send_error"); }
    };
    pc.onconnectionstatechange = () => {
      if (!settled && pc.connectionState === "failed") fail("peer_connection_failed");
    };
    socket.onopen = () => socket.send(JSON.stringify({ type: "signed_context",
      principal_context: headers["x-flow-principal"], timestamp: headers["x-flow-timestamp"],
      signature: headers["x-flow-signature"] }));
    // Serialize incoming SDP/ICE processing without mixing local and remote candidates.
    let processing = Promise.resolve();
    socket.onmessage = (event) => {
      processing = processing.then(async () => {
        if (settled) return;
        const frame = JSON.parse(event.data);
        if (frame.type === "error") {
          const codes = ["authentication_failed", "authentication_timeout", "principal_context_revoked",
            "authentication_unavailable", "permission_denied", "service_instance_unavailable",
            "signaling_unavailable", "rate_limit_exceeded", "invalid_room", "room_not_found",
            "room_full", "invalid_signal"];
          fail(codes.includes(frame.code) ? `signaling_${frame.code}` : "signaling_error");
          return;
        }
        if (frame.type === "authenticated" || frame.type === "peer_joined") {
          stage = "peer_negotiation";
          remote = frame.type === "authenticated" ? frame.peers?.[0]?.principal_id : frame.peer.principal_id;
          if (remote) for (const candidate of outgoing.splice(0)) send("ice_candidate", remote, candidate);
          await offer();
        } else if (frame.type === "signal") {
          remote = frame.sender;
          if (frame.kind === "offer" || frame.kind === "answer") {
            await pc.setRemoteDescription({ type: frame.kind, sdp: frame.payload.sdp });
            for (const candidate of incoming.splice(0)) await pc.addIceCandidate(candidate);
            if (frame.kind === "offer") {
              const answer = await pc.createAnswer();
              await pc.setLocalDescription(answer);
              send("answer", remote, { sdp: answer.sdp });
            }
          } else if (frame.kind === "ice_candidate") {
            if (pc.remoteDescription) await pc.addIceCandidate(frame.payload);
            else incoming.push(frame.payload);
          }
        }
      }).catch(() => fail("signaling_processing_error"));
    };
    socket.onerror = () => fail("signaling_socket_error");
    socket.onclose = () => { if (!settled && !finishing) fail("signaling_socket_closed"); };
    return result;
  }, { connection, headers, offerer, iceTransportPolicy });
  const first = start(pageA, connections[0], true).catch(() => ({ passed: false, code: "peer_browser_error" }));
  await new Promise((done) => setTimeout(done, 1200));
  const second = start(pageB, connections[1], false).catch(() => ({ passed: false, code: "peer_browser_error" }));
  return Promise.all([first, second]);
}
