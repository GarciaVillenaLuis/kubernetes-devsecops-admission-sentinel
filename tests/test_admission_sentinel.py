#!/usr/bin/env python3
"""
Unit tests for Kubernetes DevSecOps Admission Sentinel CLI
Author: Luis García Villena
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from k8s_admission_sentinel import KubernetesSecurityAuditor


class TestKubernetesSecurityAuditor(unittest.TestCase):

    def setUp(self):
        self.auditor_restricted = KubernetesSecurityAuditor(target_level="restricted")
        self.auditor_baseline = KubernetesSecurityAuditor(target_level="baseline")

    def test_invalid_security_level(self):
        with self.assertRaises(ValueError):
            KubernetesSecurityAuditor(target_level="invalid_level")

    def test_clean_hardened_workload(self):
        manifest = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "secure-service", "namespace": "prod"},
            "spec": {
                "template": {
                    "spec": {
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001},
                        "containers": [{
                            "name": "worker",
                            "image": "secure:v1",
                            "securityContext": {
                                "privileged": False,
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}
                            },
                            "resources": {
                                "limits": {"cpu": "100m", "memory": "128Mi"}
                            }
                        }]
                    }
                }
            }
        }
        res = self.auditor_restricted.audit_workload(manifest)
        self.assertEqual(res["admission_decision"], "ALLOWED")
        self.assertEqual(res["violations_count"], 0)
        self.assertEqual(res["compliance_score"], 100.0)

    def test_privileged_container_denied(self):
        manifest = {
            "kind": "Pod",
            "metadata": {"name": "bad-pod", "namespace": "default"},
            "spec": {
                "containers": [{
                    "name": "bad-c",
                    "securityContext": {"privileged": True}
                }]
            }
        }
        res = self.auditor_baseline.audit_workload(manifest)
        self.assertEqual(res["admission_decision"], "DENIED")
        violations = [v["id"] for v in res["violations"]]
        self.assertIn("PSS-01", violations)

    def test_host_namespace_violations(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "host-ns-app"},
            "spec": {
                "template": {
                    "spec": {
                        "hostNetwork": True,
                        "hostPID": True,
                        "containers": [{"name": "app"}]
                    }
                }
            }
        }
        res = self.auditor_baseline.audit_workload(manifest)
        self.assertEqual(res["admission_decision"], "DENIED")
        violations = [v["id"] for v in res["violations"]]
        self.assertIn("PSS-02", violations)

    def test_admission_review_webhook_generation(self):
        review_req = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "1234-5678",
                "object": {
                    "kind": "Pod",
                    "metadata": {"name": "test-webhook"},
                    "spec": {
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 5000},
                        "containers": [{
                            "name": "c1",
                            "securityContext": {
                                "privileged": False,
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}
                            },
                            "resources": {"limits": {"cpu": "1", "memory": "1Gi"}}
                        }]
                    }
                }
            }
        }
        resp = self.auditor_restricted.generate_admission_response(review_req)
        self.assertEqual(resp["kind"], "AdmissionReview")
        self.assertEqual(resp["response"]["uid"], "1234-5678")
        self.assertTrue(resp["response"]["allowed"])
        self.assertEqual(resp["response"]["status"]["code"], 200)

    def test_parse_manifest_json(self):
        json_data = json.dumps({"kind": "Pod", "metadata": {"name": "json-pod"}})
        docs = self.auditor_restricted.parse_manifest(json_data)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["metadata"]["name"], "json-pod")


if __name__ == "__main__":
    unittest.main()
