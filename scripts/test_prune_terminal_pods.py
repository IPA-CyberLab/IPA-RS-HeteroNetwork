import datetime
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "prune_terminal_pods", Path(__file__).with_name("prune-terminal-pods.py"))
prune = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prune)


class PodCleanupTest(unittest.TestCase):
    def setUp(self):
        self.cutoff = datetime.datetime(2026, 11, 9, tzinfo=datetime.timezone.utc)
        self.roster = {"hosts": {"dead": "node-a", "live": "node-b"},
                       "node_states": {"dead": {"state": "stopped", "reason": "retired"}}}
        self.nodes = [{"metadata": {"name": "dead"}, "status": {"conditions": [
            {"type": "Ready", "status": "Unknown", "lastTransitionTime": "2026-10-01T00:00:00Z"}]}}]

    def pod(self, phase="Running", node="live", created="2026-10-01T00:00:00Z", deleted=None,
            finished="2026-10-02T00:00:00Z"):
        metadata = {"namespace": "test", "name": "pod-one", "uid": "3b349294-222f-47ff-b99a-ef94d10713be",
                    "creationTimestamp": created}
        if deleted:
            metadata["deletionTimestamp"] = deleted
        status = {"phase": phase}
        if phase in ("Failed", "Succeeded") and finished:
            status["containerStatuses"] = [{"state": {"terminated": {"finishedAt": finished}}}]
        return {"metadata": metadata, "status": status, "spec": {"nodeName": node}}

    def test_old_terminal_and_stale_retired_node_pods_are_selected(self):
        terminal = self.pod(phase="Failed")
        terminating = self.pod(node="dead", deleted="2026-10-20T00:00:00Z")
        selected = prune.select_pods(self.roster, self.nodes, [terminal, terminating], self.cutoff)
        self.assertEqual([p["reason"] for p in selected], ["terminal", "stopped_node_terminating"])

    def test_running_recent_and_live_node_terminating_pods_are_preserved(self):
        pods = [self.pod(), self.pod(phase="Succeeded", created="2026-11-09T01:00:00Z"),
                self.pod(node="live", deleted="2026-10-20T00:00:00Z"),
                self.pod(node="dead", deleted="2026-11-09T01:00:00Z")]
        self.assertEqual(prune.select_pods(self.roster, self.nodes, pods, self.cutoff), [])

    def test_old_pod_with_recent_or_unknown_finish_is_preserved(self):
        pods = [self.pod(phase="Failed", finished="2026-11-09T01:00:00Z"),
                self.pod(phase="Failed", finished=None)]
        self.assertEqual(prune.select_pods(self.roster, self.nodes, pods, self.cutoff), [])

    def test_stopped_node_that_is_ready_is_never_treated_as_dead(self):
        self.nodes[0]["status"]["conditions"][0]["status"] = "True"
        pod = self.pod(node="dead", deleted="2026-10-20T00:00:00Z")
        self.assertEqual(prune.select_pods(self.roster, self.nodes, [pod], self.cutoff), [])

    def test_missing_uid_or_invalid_roster_fails_closed(self):
        pod = self.pod(phase="Failed")
        pod["metadata"]["uid"] = "not-a-uuid"
        self.assertEqual(prune.select_pods(self.roster, self.nodes, [pod], self.cutoff), [])
        self.roster["node_states"]["unknown"] = {"state": "stopped", "reason": "bad"}
        with self.assertRaises(ValueError):
            prune.select_pods(self.roster, self.nodes, [self.pod(phase="Failed")], self.cutoff)


if __name__ == "__main__":
    unittest.main()
