#!/usr/bin/env python3
"""Public gateway health voting and narrowly scoped DNS reconciliation.

Each voter has its own Kubernetes identity and may write only its own vote.
The publisher uses a fixed membership majority, fresh observations and CAS.
No Cloudflare credentials, user credentials or private keys are read here.
"""
import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_BYTES = 256 * 1024
ERROR_KINDS = {"ok", "timeout", "tls", "network", "http", "body"}
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def require(value, message):
    if not value:
        raise ValueError(message)


def dns_name(value):
    require(isinstance(value, str) and len(value) <= 253, "invalid DNS name")
    precise = value[2:] if value.startswith("*.") else value
    require("." in precise and all(LABEL.fullmatch(x) for x in precise.split(".")), "invalid DNS name")
    return value


def validate_config(raw):
    require(isinstance(raw, dict) and raw.get("schema_version") == 1, "invalid configuration version")
    allowed = {"schema_version", "namespace", "dns_namespace", "dns_resource", "state_resource",
               "members", "origins", "records", "probe", "fresh_seconds", "interval_seconds",
               "down_samples", "up_samples", "enabled", "all_down_policy"}
    require(set(raw) == allowed, "invalid configuration fields")
    for key in ("namespace", "dns_namespace", "dns_resource", "state_resource"):
        require(isinstance(raw[key], str) and LABEL.fullmatch(raw[key]), "invalid resource name")
    members, origins = raw["members"], raw["origins"]
    require(isinstance(members, list) and 3 <= len(members) <= 9, "membership must contain 3-9 voters")
    require(isinstance(origins, list) and 1 <= len(origins) <= 16, "invalid origin inventory")
    for member in members:
        require(set(member) == {"id", "node", "vote_resource"}, "invalid member fields")
        for key in ("id", "node", "vote_resource"):
            require(isinstance(member[key], str) and LABEL.fullmatch(member[key]), "invalid voter identity")
    for key in ("id", "node", "vote_resource"):
        require(len({x[key] for x in members}) == len(members), "voters must have distinct identities and nodes")
    for origin in origins:
        require(set(origin) == {"id", "address"} and LABEL.fullmatch(origin["id"]), "invalid origin fields")
        address = ipaddress.ip_address(origin["address"])
        require(str(address) == origin["address"] and address.is_global, "origin must be a canonical public IP")
    for key in ("id", "address"):
        require(len({x[key] for x in origins}) == len(origins), "duplicate origin")
    require(isinstance(raw["records"], list) and 1 <= len(raw["records"]) <= 32, "invalid managed DNS names")
    for name in raw["records"]:
        dns_name(name)
    require(len(set(raw["records"])) == len(raw["records"]), "duplicate managed DNS name")
    probe = raw["probe"]
    require(set(probe) == {"hostname", "path", "port", "timeout_seconds", "expected_body", "check_http_redirect"}, "invalid probe fields")
    require(not dns_name(probe["hostname"]).startswith("*."), "probe requires a precise hostname")
    require(isinstance(probe["path"], str) and re.fullmatch(r"/[a-zA-Z0-9/_-]{1,120}", probe["path"]), "invalid probe path")
    require(type(probe["port"]) is int and probe["port"] == 443, "HTTPS probe must use port 443")
    require(type(probe["timeout_seconds"]) in (int, float) and 0.2 <= probe["timeout_seconds"] <= 5, "invalid probe timeout")
    require(isinstance(probe["expected_body"], str) and 1 <= len(probe["expected_body"].encode()) <= 256, "invalid probe marker")
    require(type(probe["check_http_redirect"]) is bool, "invalid HTTP probe setting")
    for key, lo, hi in (("fresh_seconds", 10, 120), ("interval_seconds", 2, 30), ("down_samples", 1, 10), ("up_samples", 1, 10)):
        require(type(raw[key]) is int and lo <= raw[key] <= hi, "invalid timing or hysteresis setting")
    require(raw["fresh_seconds"] >= 3 * raw["interval_seconds"], "freshness must cover at least three intervals")
    require(type(raw["enabled"]) is bool, "invalid publisher enabled setting")
    require(raw["all_down_policy"] in ("retain", "withdraw"), "invalid all-down policy")
    return raw


def digest(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def parse_document(raw):
    require(isinstance(raw, (str, bytes)) and len(raw) <= MAX_BYTES, "document exceeds bound")
    return json.loads(raw)


def usable_vote(config, member, document, now):
    try:
        require(isinstance(document, dict) and set(document) == {"schema_version", "config_digest", "voter_id", "node", "sample_id", "observed_at", "origins"}, "invalid vote fields")
        require(document["schema_version"] == 1 and document["config_digest"] == digest(config), "vote configuration differs")
        require(document["voter_id"] == member["id"] and document["node"] == member["node"], "vote identity differs")
        require(isinstance(document["sample_id"], str) and re.fullmatch(r"[0-9a-f]{32}", document["sample_id"]), "invalid sample identity")
        stamp = document["observed_at"]
        require(type(stamp) in (int, float) and math.isfinite(stamp) and now - config["fresh_seconds"] <= stamp <= now + 3, "stale or future vote")
        require(isinstance(document["origins"], dict) and set(document["origins"]) == {x["id"] for x in config["origins"]}, "vote origin inventory differs")
        for result in document["origins"].values():
            require(isinstance(result, dict) and set(result) == {"healthy", "reason"}, "invalid result")
            require(type(result["healthy"]) is bool and result["reason"] in ERROR_KINDS, "invalid health result")
            require(result["healthy"] == (result["reason"] == "ok"), "inconsistent health result")
        return document
    except (ValueError, KeyError, TypeError):
        return None


def current_targets(config, endpoint):
    require(endpoint.get("apiVersion") == "externaldns.k8s.io/v1alpha1" and endpoint.get("kind") == "DNSEndpoint", "unexpected DNS resource")
    metadata = endpoint["metadata"]
    require(metadata["name"] == config["dns_resource"] and metadata["namespace"] == config["dns_namespace"], "unexpected DNS owner")
    require(metadata.get("labels", {}).get("dns.heterocloud.io/publish") == "true", "DNS resource is not published")
    require(not metadata.get("deletionTimestamp"), "DNS resource is deleting")
    entries = endpoint["spec"]["endpoints"]
    known = {x["address"] for x in config["origins"]}
    selected = [x for x in entries if x.get("dnsName") in config["records"]]
    require(len(selected) == len(config["records"]) and len({x["dnsName"] for x in selected}) == len(selected), "managed DNS inventory differs")
    sets = []
    for entry in selected:
        expected_type = "A" if all(ipaddress.ip_address(x).version == 4 for x in known) else "AAAA"
        require(all(ipaddress.ip_address(x).version == (4 if expected_type == "A" else 6) for x in known), "mixed address families require separate pools")
        require(entry.get("recordType") == expected_type, "unexpected DNS record type")
        require(isinstance(entry.get("targets"), list) and set(entry["targets"]) <= known and len(entry["targets"]) == len(set(entry["targets"])), "unknown DNS target")
        sets.append(set(entry["targets"]))
    require(all(x == sets[0] for x in sets), "managed DNS names have differing targets")
    return sorted(sets[0])


def new_state(config, published):
    return {"schema_version": 1, "config_digest": digest(config),
            "origins": {x["id"]: {"active": x["address"] in published,
                "streak_vote": None, "streak": 0, "last_samples": {}}
                for x in config["origins"]}}


def valid_state(config, value):
    try:
        require(isinstance(value, dict) and value["schema_version"] == 1 and value["config_digest"] == digest(config), "state configuration differs")
        require(set(value["origins"]) == {x["id"] for x in config["origins"]}, "state inventory differs")
        members = {x["id"] for x in config["members"]}
        for state in value["origins"].values():
            require(set(state) == {"active", "streak_vote", "streak", "last_samples"}, "invalid origin state")
            require(type(state["active"]) is bool and (state["streak_vote"] is None or type(state["streak_vote"]) is bool), "invalid committed state")
            require(type(state["streak"]) is int and 0 <= state["streak"] <= 10, "invalid observation streak")
            require(isinstance(state["last_samples"], dict) and set(state["last_samples"]) <= members, "invalid state membership")
            require(all(isinstance(s, str) and re.fullmatch(r"[0-9a-f]{32}", s) for s in state["last_samples"].values()), "invalid consumed observation")
        return True
    except (ValueError, TypeError, KeyError):
        return False


def decide(config, votes, previous, published, now):
    state = copy.deepcopy(previous) if valid_state(config, previous) else new_state(config, published)
    valid = {m["id"]: usable_vote(config, m, votes.get(m["id"]), now) for m in config["members"]}
    valid = {k: v for k, v in valid.items() if v is not None}
    majority = len(config["members"]) // 2 + 1
    results = {}
    for origin in config["origins"]:
        key = origin["id"]
        status = state["origins"][key]
        up = [k for k, v in valid.items() if v["origins"][key]["healthy"]]
        down = [k for k, v in valid.items() if not v["origins"][key]["healthy"]]
        opinion = True if len(up) >= majority else False if len(down) >= majority else None
        supporters = up if opinion is True else down if opinion is False else []
        fresh = [k for k in supporters if status["last_samples"].get(k) != valid[k]["sample_id"]]
        if opinion is None:
            status["streak_vote"], status["streak"] = None, 0
        elif len(fresh) >= majority:
            status["streak"] = min(10, status["streak"] + 1) if status["streak_vote"] == opinion else 1
            status["streak_vote"] = opinion
            status["last_samples"] = {k: v["sample_id"] for k, v in valid.items()}
            needed = config["up_samples"] if opinion else config["down_samples"]
            if status["streak"] >= needed:
                status["active"] = opinion
        results[key] = {"healthy_votes": len(up), "unhealthy_votes": len(down),
                        "decision": "healthy" if opinion is True else "unhealthy" if opinion is False else "unknown",
                        "active": status["active"], "streak": status["streak"]}
    desired = sorted(x["address"] for x in config["origins"] if state["origins"][x["id"]]["active"])
    all_down = not desired and all(x["decision"] == "unhealthy" for x in results.values())
    # An expired/missing observation never authorizes withdrawal of an entire zone.
    if not desired and (not all_down or config["all_down_policy"] == "retain"):
        desired = published
    if not config["enabled"]:
        desired = published
    report = {"schema_version": 1, "config_digest": digest(config), "observed_at": now,
              "enabled": config["enabled"], "majority_required": majority, "membership_size": len(config["members"]),
              "fresh_voters": len(valid), "origins": results, "published_targets": desired,
              "all_down": all_down, "all_down_policy": config["all_down_policy"],
              "all_down_retained": all_down and config["all_down_policy"] == "retain"}
    return state, desired, report


def dns_patch(config, endpoint, desired):
    current_targets(config, endpoint)
    operations = [{"op": "test", "path": "/metadata/resourceVersion", "value": endpoint["metadata"]["resourceVersion"]},
                  {"op": "test", "path": "/metadata/uid", "value": endpoint["metadata"]["uid"]}]
    for index, entry in enumerate(endpoint["spec"]["endpoints"]):
        if entry["dnsName"] in config["records"] and entry["targets"] != desired:
            operations.extend([{"op": "test", "path": f"/spec/endpoints/{index}", "value": entry},
                               {"op": "replace", "path": f"/spec/endpoints/{index}/targets", "value": desired}])
    return operations if len(operations) > 2 else None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class ApiError(Exception):
    def __init__(self, status):
        self.status = status


class Kubernetes:
    def __init__(self):
        self.root = Path("/var/run/secrets/kubernetes.io/serviceaccount")
        host, port = os.environ["KUBERNETES_SERVICE_HOST"], os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]
        self.base = f"https://[{host}]:{port}" if ":" in host else f"https://{host}:{port}"
        context = ssl.create_default_context(cafile=str(self.root / "ca.crt"))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def call(self, method, path, value=None, content_type="application/json"):
        headers = {"Authorization": "Bearer " + (self.root / "token").read_text().strip(), "Content-Type": content_type}
        data = None if value is None else json.dumps(value, separators=(",", ":")).encode()
        request = urllib.request.Request(self.base + path, method=method, headers=headers, data=data)
        try:
            with self.opener.open(request, timeout=5) as response:
                raw = response.read(MAX_BYTES + 1)
                require(len(raw) <= MAX_BYTES, "API response exceeds bound")
                return parse_document(raw)
        except urllib.error.HTTPError as error:
            raise ApiError(error.code) from None


def cm_path(namespace, name):
    return f"/api/v1/namespaces/{namespace}/configmaps/{name}"


def endpoint_path(config):
    return f"/apis/externaldns.k8s.io/v1alpha1/namespaces/{config['dns_namespace']}/dnsendpoints/{config['dns_resource']}"


def cm_patch(document, values):
    operations = [{"op": "test", "path": "/metadata/resourceVersion", "value": document["metadata"]["resourceVersion"]},
                  {"op": "test", "path": "/metadata/uid", "value": document["metadata"]["uid"]}]
    data = {**document.get("data", {}), **values}
    operations.append({"op": "add", "path": "/data", "value": data})
    return operations


class OriginConnection(http.client.HTTPSConnection):
    def __init__(self, address, config):
        super().__init__(config["hostname"], config["port"], timeout=config["timeout_seconds"], context=ssl.create_default_context())
        self.address = address

    def connect(self):
        connection = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
        except Exception:
            connection.close()
            raise


def probe_origin(origin, probe):
    client = None
    try:
        client = OriginConnection(origin["address"], probe)
        client.request("GET", probe["path"], headers={"Host": probe["hostname"], "User-Agent": "HeteroNetwork-DNS-Quorum/1.0", "Connection": "close"})
        response = client.getresponse()
        if response.status != 200:
            return {"healthy": False, "reason": "http"}
        if response.read(257) != probe["expected_body"].encode():
            return {"healthy": False, "reason": "body"}
        if probe["check_http_redirect"]:
            client.close()
            client = http.client.HTTPConnection(origin["address"], 80, timeout=probe["timeout_seconds"])
            client.request("GET", probe["path"], headers={"Host": probe["hostname"], "User-Agent": "HeteroNetwork-DNS-Quorum/1.0", "Connection": "close"})
            response = client.getresponse()
            if response.status not in (301, 302, 307, 308) or response.getheader("Location") != f"https://{probe['hostname']}{probe['path']}":
                return {"healthy": False, "reason": "http"}
        return {"healthy": True, "reason": "ok"}
    except (TimeoutError, socket.timeout):
        return {"healthy": False, "reason": "timeout"}
    except ssl.SSLError:
        return {"healthy": False, "reason": "tls"}
    except (OSError, http.client.HTTPException):
        return {"healthy": False, "reason": "network"}
    finally:
        if client:
            client.close()


def vote_once(config, voter_id, api):
    member = next(x for x in config["members"] if x["id"] == voter_id)
    require(os.environ["NODE_NAME"] == member["node"], "voter is running on an unexpected node")
    with ThreadPoolExecutor(max_workers=min(8, len(config["origins"]))) as executor:
        results = list(executor.map(lambda x: probe_origin(x, config["probe"]), config["origins"]))
    vote = {"schema_version": 1, "config_digest": digest(config), "voter_id": voter_id,
            "node": member["node"], "sample_id": uuid.uuid4().hex, "observed_at": time.time(),
            "origins": {x["id"]: result for x, result in zip(config["origins"], results)}}
    path = cm_path(config["namespace"], member["vote_resource"])
    document = api.call("GET", path)
    api.call("PATCH", path, cm_patch(document, {"vote.json": json.dumps(vote, separators=(",", ":"))}), "application/json-patch+json")
    return {"component": "voter", "voter_id": voter_id, "healthy_origins": sum(x["healthy"] for x in results), "origin_count": len(results)}


def publish_once(config, api):
    path = cm_path(config["namespace"], config["state_resource"])
    document = api.call("GET", path)
    identity = os.environ["POD_UID"]
    require(re.fullmatch(r"[a-f0-9-]{36}", identity), "invalid publisher identity")
    raw_lease = document.get("data", {}).get("lease.json", "")
    lease = parse_document(raw_lease) if raw_lease else {}
    now = time.time()
    if lease.get("owner") != identity and lease.get("expires_at", 0) > now:
        return {"component": "publisher", "role": "standby"}
    takeover = lease.get("owner") != identity
    lease = {"owner": identity, "expires_at": now + 45}
    api.call("PATCH", path, cm_patch(document, {"lease.json": json.dumps(lease, separators=(",", ":"))}), "application/json-patch+json")
    endpoint = api.call("GET", endpoint_path(config))
    # A new leader changes the DNS object's version before it consumes votes.
    # A delayed write from the previous leader then fails its DNS CAS test.
    if takeover:
        fence = [{"op": "test", "path": "/metadata/resourceVersion", "value": endpoint["metadata"]["resourceVersion"]},
                 {"op": "test", "path": "/metadata/uid", "value": endpoint["metadata"]["uid"]},
                 {"op": "add", "path": "/metadata/annotations", "value": {**endpoint["metadata"].get("annotations", {}), "dns.heterocloud.io/quorum-writer": identity}}]
        endpoint = api.call("PATCH", endpoint_path(config), fence, "application/json-patch+json")
    published = current_targets(config, endpoint)
    votes = {}
    for member in config["members"]:
        try:
            document = api.call("GET", cm_path(config["namespace"], member["vote_resource"]))
            raw = document.get("data", {}).get("vote.json", "")
            votes[member["id"]] = parse_document(raw) if raw else None
        except (ApiError, ValueError, KeyError, TypeError):
            votes[member["id"]] = None
    document = api.call("GET", path)
    current_lease = parse_document(document["data"]["lease.json"])
    require(current_lease["owner"] == identity and current_lease["expires_at"] - time.time() > 6, "publisher lease expired")
    raw = document.get("data", {}).get("state.json", "")
    previous = parse_document(raw) if raw else None
    state, desired, report = decide(config, votes, previous, published, time.time())
    # Commit consumed observations first. A competing publisher must refetch
    # the state after a conflict and cannot count those observations twice.
    api.call("PATCH", path, cm_patch(document, {"state.json": json.dumps(state, separators=(",", ":")), "status.json": json.dumps(report, separators=(",", ":"))}), "application/json-patch+json")
    patch = dns_patch(config, endpoint, desired)
    if patch:
        # This guards against another publisher committing a newer decision.
        latest = api.call("GET", path)
        latest_lease = parse_document(latest["data"]["lease.json"])
        require(latest_lease["owner"] == identity and latest_lease["expires_at"] - time.time() > 6, "publisher lease expired")
        require(latest["data"]["state.json"] == json.dumps(state, separators=(",", ":")), "newer publisher decision exists")
        api.call("PATCH", endpoint_path(config), patch, "application/json-patch+json")
    return {"component": "publisher", "enabled": config["enabled"], "fresh_voters": report["fresh_voters"],
            "majority_required": report["majority_required"], "published_targets": desired,
            "all_down": report["all_down"], "dns_changed": patch is not None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("voter", "publisher"))
    parser.add_argument("--config", default="/config/pool.json")
    parser.add_argument("--voter-id")
    args = parser.parse_args()
    config = validate_config(parse_document(Path(args.config).read_bytes()))
    if args.role == "voter":
        require(args.voter_id in {x["id"] for x in config["members"]}, "unknown voter")
    api = Kubernetes()
    while True:
        started = time.monotonic()
        Path("/tmp/loop-progress").touch()
        try:
            report = vote_once(config, args.voter_id, api) if args.role == "voter" else publish_once(config, api)
            Path("/tmp/last-success").touch()
            print(json.dumps(report, separators=(",", ":")), flush=True)
        except ApiError as error:
            print(json.dumps({"component": args.role, "error": "kubernetes_api", "status": error.status}), flush=True)
        except Exception:
            # Exception text may include request headers; never log it.
            print(json.dumps({"component": args.role, "error": "reconciliation_failed"}), flush=True)
        time.sleep(max(0.2, config["interval_seconds"] - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
