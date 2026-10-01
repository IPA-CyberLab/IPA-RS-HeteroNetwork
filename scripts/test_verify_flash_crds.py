#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).with_name("verify_flash_crds.py")
SPEC = importlib.util.spec_from_file_location("verify_flash_crds", MODULE_PATH)
assert SPEC and SPEC.loader
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


def crd(name, spec):
    return {
        "metadata": {"name": name},
        "spec": {"versions": [{
            "name": verify.VERSION,
            "served": True,
            "storage": True,
            "schema": {"openAPIV3Schema": {"properties": {"spec": spec}}},
        }]},
        "status": {"conditions": [{"type": "Established", "status": "True"}]},
    }


def documents():
    application = {
        "spec": {"source": {"targetRevision": "v0.1.38"}},
        "status": {
            "sync": {
                "status": "Synced",
                "comparedTo": {"source": {"targetRevision": "v0.1.38"}},
            },
            "health": {"status": "Healthy"},
            "resources": [
                {"kind": "CustomResourceDefinition", "name": verify.DEVICE_CRD, "status": "Synced"},
                {"kind": "CustomResourceDefinition", "name": verify.JOB_CRD, "status": "Synced"},
                {"kind": "CustomResourceDefinition", "name": verify.SERVICE_CRD, "status": "Synced"},
            ],
        },
    }
    device = crd(verify.DEVICE_CRD, {
        "properties": {
            "private_assignments": {
                "maxItems": 256,
                "items": {
                    "type": "string",
                    "minLength": 36,
                    "maxLength": 36,
                    "pattern": verify.UUID_PATTERN,
                },
            },
        },
        "x-kubernetes-validations": [{"rule": verify.GPU_TYPE_RULE}],
    })
    job = crd(verify.JOB_CRD, {
        "properties": {
            "gpu_type": {"type": "string", "nullable": True},
            "count": {"type": "integer", "minimum": 1, "maximum": 1},
        },
        "x-kubernetes-validations": [{"rule": verify.OPTIONAL_GPU_TYPE_RULE}],
    })
    service = crd(verify.SERVICE_CRD, {
        "properties": {"workload": {"properties": {
            "secret_env": {"type": "object", "additionalProperties": {"type": "string"}},
            "secret_files": {"type": "object", "additionalProperties": {"type": "string"}},
            "rootfs_storage_gib": {
                "type": "integer", "minimum": 1, "maximum": 1_000_000, "nullable": True,
            },
        }}},
    })
    return application, device, job, service


class VerifyFlashCrdsTests(unittest.TestCase):
    def test_accepts_current_release_contract(self):
        result = verify.validate(*documents())
        self.assertTrue(result[verify.DEVICE_CRD]["assignment_contract"])
        self.assertTrue(result[verify.JOB_CRD]["gpu_type_contract"])
        self.assertTrue(result[verify.SERVICE_CRD]["secret_env_contract"])
        self.assertTrue(result[verify.SERVICE_CRD]["legacy_secret_contract"])
        self.assertTrue(result[verify.SERVICE_CRD]["rootfs_storage_contract"])

    def test_rejects_schema_that_would_prune_requested_rootfs(self):
        application, device, job, service = documents()
        workload = service["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["workload"]
        del workload["properties"]["rootfs_storage_gib"]
        with self.assertRaisesRegex(RuntimeError, "writable disk"):
            verify.validate(application, device, job, service)

    def test_rejects_unbounded_or_non_uuid_assignments(self):
        application, device, job, service = documents()
        assignments = device["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
        del assignments["properties"]["spec"]["properties"]["private_assignments"]["maxItems"]
        with self.assertRaisesRegex(RuntimeError, "bounded lowercase UUID"):
            verify.validate(application, device, job, service)

    def test_rejects_missing_job_gpu_type_rule(self):
        application, device, job, service = documents()
        schema = job["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
        schema["properties"]["spec"]["x-kubernetes-validations"] = []
        with self.assertRaisesRegex(RuntimeError, "canonical optional GPU type"):
            verify.validate(application, device, job, service)

    def test_rejects_crd_that_is_not_established(self):
        application, device, job, service = documents()
        job["status"]["conditions"][0]["status"] = "False"
        with self.assertRaisesRegex(RuntimeError, "not Established"):
            verify.validate(application, device, job, service)

    def test_rejects_stale_application_comparison(self):
        application, device, job, service = documents()
        application["status"]["sync"]["comparedTo"]["source"]["targetRevision"] = "v0.1.31"
        with self.assertRaisesRegex(RuntimeError, "desired revision"):
            verify.validate(application, device, job, service)

    def test_rejects_schema_that_would_prune_secret_references(self):
        application, device, job, service = documents()
        secret_env = service["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["workload"]["properties"]["secret_env"]
        del secret_env["additionalProperties"]
        with self.assertRaisesRegex(RuntimeError, "preserve secret environment references"):
            verify.validate(application, device, job, service)

    def test_rejects_schema_that_would_prune_legacy_secret_references(self):
        application, device, job, service = documents()
        secret_files = service["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["workload"]["properties"]["secret_files"]
        del secret_files["additionalProperties"]
        with self.assertRaisesRegex(RuntimeError, "preserve legacy secret references"):
            verify.validate(application, device, job, service)


if __name__ == "__main__":
    unittest.main()
