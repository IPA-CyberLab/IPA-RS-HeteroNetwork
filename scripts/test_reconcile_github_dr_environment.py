import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("github_dr", Path(__file__).with_name("reconcile-github-dr-environment.py"))
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)
CONFIG = {"repository": "owner/repo", "environment": "dr", "allowed_branch": "master", "required_secret_name": "BACKUP_KEY"}


class FakeGitHub:
    def __init__(self, exists=True, policies=None, secret=True):
        self.env = {"name": "dr", "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}} if exists else None
        self.policies = [{"name": "master", "type": "branch"}] if policies is None else policies
        self.secret = secret
        self.writes = []

    def request(self, method, path, value=None, allow_missing=False):
        if method == "PUT":
            self.writes.append((method, path, value))
            self.env = {"name": "dr", **value}
            return self.env
        if method == "POST":
            self.writes.append((method, path, value))
            self.policies.append(value)
            return value
        if path.endswith("/deployment-branch-policies"):
            return {"branch_policies": self.policies}
        if path.endswith("/secrets"):
            return {"secrets": [{"name": "BACKUP_KEY"}] if self.secret else []}
        return self.env


class GitHubRecoveryEnvironmentTests(unittest.TestCase):
    def test_existing_environment_is_idempotent_and_never_reads_secret_value(self):
        fake = FakeGitHub()
        self.assertTrue(subject.reconcile(CONFIG, fake)["required_secret_present"])
        self.assertEqual(fake.writes, [])

    def test_missing_environment_is_created_fail_closed_then_restricted(self):
        fake = FakeGitHub(exists=False, policies=[])
        subject.reconcile(CONFIG, fake)
        self.assertEqual([call[0] for call in fake.writes], ["PUT", "POST"])
        self.assertEqual(fake.writes[0][2]["deployment_branch_policy"],
                         {"protected_branches": False, "custom_branch_policies": True})
        self.assertEqual(fake.writes[1][2], {"name": "master", "type": "branch"})

    def test_different_or_broader_restrictions_are_not_overwritten(self):
        fake = FakeGitHub(policies=[{"name": "master", "type": "branch"}, {"name": "*", "type": "branch"}])
        with self.assertRaisesRegex(ValueError, "only the declared branch"):
            subject.reconcile(CONFIG, fake)
        self.assertEqual(fake.writes, [])
        fake = FakeGitHub()
        fake.env["deployment_branch_policy"] = None
        with self.assertRaisesRegex(ValueError, "refusing to weaken"):
            subject.reconcile(CONFIG, fake)
        self.assertEqual(fake.writes, [])

    def test_missing_secret_or_invalid_config_fails(self):
        with self.assertRaisesRegex(ValueError, "secret is missing"):
            subject.reconcile(CONFIG, FakeGitHub(secret=False))
        with self.assertRaisesRegex(ValueError, "repository"):
            subject.reconcile({**CONFIG, "repository": "owner/repo/extra"}, FakeGitHub())


if __name__ == "__main__":
    unittest.main()
