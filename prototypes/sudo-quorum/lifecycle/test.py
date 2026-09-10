"""Container-only lifecycle test. Never run directly on a host."""
import os
from pathlib import Path
import subprocess


def main():
    if not Path("/.dockerenv").exists() or os.getuid() != 0:
        raise SystemExit("requires a disposable root container")
    root = Path("/opt/quorum-lifecycle")
    if Path(__file__).resolve().parent != root:
        raise SystemExit("requires the isolated image layout")
    subprocess.run(["/usr/sbin/chpasswd"], input=b"fixture:disposable-test-password\n", check=True)
    # Keep the distribution's policy, audit, I/O plugins and PAM auth/account stack.
    conf = Path("/etc/sudo.conf")
    original = conf.read_text()
    policy = Path("/etc/sudoers.d/quorum-lifecycle")
    policy.write_text("Defaults:fixture timestamp_timeout=0, passwd_tries=1, fdexec=always\n"
                      "fixture ALL=(root) CWD=/opt/quorum-lifecycle/work PASSWD: /opt/quorum-lifecycle/command\n")
    policy.chmod(0o440)
    subprocess.run(["/usr/sbin/visudo", "-c"], check=True, capture_output=True)
    # A real PAM session hook, not a substitute policy or bypass of password checks.
    Path("/etc/quorum-lifecycle.env").write_text("QUORUM_LIFECYCLE_SESSION=after-approval\n")
    with Path("/etc/pam.d/sudo").open("a") as pam:
        pam.write("\nsession required pam_env.so readenv=1 envfile=/etc/quorum-lifecycle.env\n")

    def invoke(command=b"/opt/quorum-lifecycle/command", password=b"disposable-test-password", options=()):
        return subprocess.run(
            [b"/usr/sbin/runuser", b"-u", b"fixture", b"--", b"/usr/bin/sudo", b"-k", b"-S", b"-p", b"",
             *options, command, b"", b"two words", b"\xff"],
            input=password + b"\n", capture_output=True, timeout=15,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})

    def plugin(symbol, filename):
        conf.write_text(original + f"\nPlugin {symbol} {root / filename}\n")

    plugin("lifecycle_witness", "witness.so")
    denied = invoke(password=b"incorrect")
    assert denied.returncode != 0 and b"WITNESS" not in denied.stdout and b"EXECUTED" not in denied.stdout
    denied = invoke(command=b"/usr/bin/true")
    assert denied.returncode != 0 and b"WITNESS" not in denied.stdout and b"EXECUTED" not in denied.stdout
    accepted = invoke()
    assert accepted.returncode == 0, "fixed fixture failed (output intentionally withheld)"
    assert b"caller_metadata=1" in accepted.stdout
    assert b"runas=1 argv=1 cwd=1 execfd=1 session_marker=0" in accepted.stdout
    assert b"EXECUTED uid=1 argv=1 cwd=1 session_marker=1" in accepted.stdout
    print(accepted.stdout.decode("ascii").strip())

    plugin("quorum_deny_gate", "deny_gate.so")
    for options in ((), (b"-E",), (b"-s",)):
        denied = invoke(options=options)
        assert denied.returncode != 0 and b"EXECUTED" not in denied.stdout
    assert b"final execution context is not bound" in invoke().stderr
    print("PASS: password rejection, sudoers rejection, post-approval environment change, deny gate and unsupported modes")
    subprocess.run(["/usr/bin/sudo", "--version"], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
