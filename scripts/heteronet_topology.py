"""Manage declared physical and network failure domains through Terraform."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy/terraform/master-only"
CONFIG = MODULE / "node-localities.json"
ROSTER = MODULE / "overlay-boot-peers.json"


def reconciler():
    spec = importlib.util.spec_from_file_location("reconcile_overlay_hierarchy", ROOT / "scripts/reconcile-overlay-hierarchy.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load locality validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def update(config, roster, host, *, remove=False, region=None, zone=None, network=None, clear_network=False):
    config = Path(config)
    if config.is_symlink() or not config.is_file():
        raise ValueError("the locality configuration must be a regular file")
    original = config.read_text(encoding="utf-8")
    data = json.loads(original)
    validator = reconciler()
    validator.load_localities(config, roster)
    known = json.loads(Path(roster).read_text(encoding="utf-8"))["hosts"]
    hosts = [host] if isinstance(host, str) else list(host)
    if not hosts or len(set(hosts)) != len(hosts) or any(name not in known for name in hosts):
        raise ValueError("nodes must be unique members of the declared overlay roster")
    if not remove and region is None and zone is None and network is None and not clear_network:
        raise ValueError("specify at least one locality field")
    for name in hosts:
        if remove:
            data["nodes"].pop(name, None)
            if name not in data["remove"]:
                data["remove"].append(name)
        else:
            entry = dict(data["nodes"].get(name, {}))
            for key, value in (("region", region), ("zone", zone), ("network", network)):
                if value is not None:
                    entry[key] = value
            if clear_network:
                entry.pop("network", None)
            data["nodes"][name] = entry
            data["remove"] = [removed for removed in data["remove"] if removed != name]
    data["nodes"] = dict(sorted(data["nodes"].items()))
    data["remove"].sort()
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=".node-localities-", dir=config.parent)
    try:
        os.fchmod(fd, config.stat().st_mode & 0o777)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        validator.load_localities(temporary, roster)
        if config.read_text(encoding="utf-8") != original:
            raise RuntimeError("locality configuration changed concurrently; retry")
        os.replace(temporary, config)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return data


def planned_changes(plan):
    allowed = ("kubernetes_labels.overlay_node_locality[", "terraform_data.overlay_locality_validation", "terraform_data.overlay_hierarchy_policy")
    changes = []
    for resource in plan.get("resource_changes", []):
        actions = resource.get("change", {}).get("actions", [])
        if actions in (["no-op"], ["read"]):
            continue
        address = resource.get("address", "")
        if not (address.startswith(allowed[0]) or address in allowed[1:]):
            raise RuntimeError(f"refusing unrelated Terraform change: {address}")
        changes.append({"resource": address, "actions": actions})
    return changes


def run_plan(args):
    reconciler().load_localities(CONFIG, ROSTER)
    if args.action == "apply":
        token_path = os.environ.get("HNN_HIERARCHY_TOKEN_FILE")
        if not token_path:
            raise ValueError("HNN_HIERARCHY_TOKEN_FILE must name a private owner token file")
        reconciler().read_token(token_path)
    if not args.work_dir.is_dir():
        raise ValueError("work directory does not exist")
    environment = os.environ.copy()
    environment.update({
        "KUBE_CONFIG_PATH": str(args.kubeconfig),
        "TF_VAR_kubeconfig_path": str(args.kubeconfig),
        "TF_VAR_ssh_private_key_path": str(args.ssh_key),
        "TF_VAR_work_dir": str(args.work_dir),
    })
    with tempfile.TemporaryDirectory(prefix="topology-plan-", dir=args.work_dir) as temporary:
        plan = str(Path(temporary) / "plan")
        subprocess.run([args.terraform, "plan", "-no-color", "-input=false",
                        "-target=terraform_data.overlay_hierarchy_policy", "-out=" + plan],
                       cwd=MODULE, env=environment, check=True)
        result = subprocess.run([args.terraform, "show", "-json", plan], cwd=MODULE,
                                env=environment, check=True, capture_output=True, text=True)
        changes = planned_changes(json.loads(result.stdout))
        print(json.dumps({"changes": changes}), flush=True)
        if args.action == "apply" and changes:
            subprocess.run([args.terraform, "apply", "-no-color", "-parallelism=1", plan],
                           cwd=MODULE, env=environment, check=True)
    return 0


def add_parser(subparsers, default_work_dir):
    topology = subparsers.add_parser("topology", help="manage site and network failure domains")
    actions = topology.add_subparsers(dest="action", required=True)
    actions.add_parser("list", help="show the declared node failure domains")
    set_cmd = actions.add_parser("set", help="set a node's declared failure domains")
    set_cmd.add_argument("hostname", nargs="+")
    set_cmd.add_argument("--region")
    set_cmd.add_argument("--zone")
    network = set_cmd.add_mutually_exclusive_group()
    network.add_argument("--network")
    network.add_argument("--clear-network", action="store_true")
    remove = actions.add_parser("remove", help="remove a node's managed locality")
    remove.add_argument("hostname", nargs="+")
    for name in ("plan", "apply"):
        command = actions.add_parser(name, help=f"{name} the declared topology through Terraform")
        command.add_argument("--work-dir", type=Path, default=default_work_dir())
        command.add_argument("--kubeconfig", type=Path)
        command.add_argument("--ssh-key", type=Path, default=Path(os.environ.get("TF_VAR_ssh_private_key_path", str(ROOT / ".key"))).expanduser())
        command.add_argument("--ssh-user", default=os.environ.get("HNN_IAC_SSH_USER", "mizuame"))
        command.add_argument("--kube-api-proxy-port", type=int, default=7443)
        command.add_argument("--terraform", default="terraform")


def dispatch(args, *, default_kubeconfig, kube_tunnel):
    if args.action == "list":
        reconciler().load_localities(CONFIG, ROSTER)
        print(CONFIG.read_text(encoding="utf-8"), end="")
    elif args.action in ("set", "remove"):
        kwargs = {} if args.action == "remove" else {
            "region": args.region, "zone": args.zone, "network": args.network,
            "clear_network": args.clear_network,
        }
        update(CONFIG, ROSTER, args.hostname, remove=args.action == "remove", **kwargs)
        print("locality updated; run 'heteronet-admin topology plan' and 'heteronet-admin topology apply'")
    else:
        if args.kubeconfig is None:
            args.kubeconfig = default_kubeconfig(args.work_dir)
        with kube_tunnel(args):
            return run_plan(args)
    return 0
