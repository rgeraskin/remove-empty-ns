"""End-to-end tests for src/app.py using a live Kubernetes cluster."""

from __future__ import annotations

import copy
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

import yaml
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.config.config_exception import ConfigException

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_PATH = REPO_ROOT / "src" / "app.py"
VERBOSE_FLAGS = {"-v", "-vv", "-vvv", "--verbose"}
VERBOSE_TEST_RUN = any(arg in VERBOSE_FLAGS for arg in sys.argv[1:])
DOUBLE_CHECK_LABEL = "remove-empty-ns/will-remove"
DEFAULT_RESOURCES_IGNORED = [
    {"apiGroup": "", "kind": "ConfigMap", "name": r"kube-root-ca\.crt"},
    {"apiGroup": "", "kind": "Secret", "name": r"default-token-\w+$"},
    {"apiGroup": "", "kind": "ServiceAccount", "name": "default"},
]
DEFAULT_API_RESOURCES_IGNORED = [
    {"apiGroup": "", "kind": r"Event$"},
    {"apiGroup": "events.k8s.io", "kind": r"Event$"},
    {"apiGroup": "coordination.k8s.io", "kind": r"Lease$"},
]


class RemoveEmptyNamespacesAppE2ETest(unittest.TestCase):
    """Exercise the remove-empty-ns app against a real cluster."""

    @classmethod
    def setUpClass(cls):
        try:
            config.load_kube_config()
        except ConfigException:
            config.load_incluster_config()

        cls.core_v1 = client.CoreV1Api()

    def setUp(self):
        self.namespace = self._unique_namespace_name()
        self.created_namespaces: set[str] = set()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.settings_path = Path(self.tmpdir.name) / "settings.yaml"

    def tearDown(self):
        for namespace in self.created_namespaces:
            try:
                self.core_v1.delete_namespace(namespace)
            except ApiException as exc:
                if exc.status != 404:
                    raise
        self.tmpdir.cleanup()

    def test_empty_namespace_marked_then_deleted(self):
        """An empty namespace should require two consecutive runs to disappear."""
        self._create_namespace()
        self._write_settings()

        self._run_app()
        self._assert_label_value("True")

        self._run_app()
        self._wait_for_namespace_absent()

    def test_namespace_with_workload_is_preserved(self):
        """A namespace containing a non-ignored resource must not be removed."""
        self._create_namespace()
        self._create_config_map()
        self._write_settings()

        self._run_app()
        self._assert_not_processed()

    def test_dry_run_mode_never_deletes(self):
        """Dry run should log actions but leave namespaces untouched."""
        self._create_namespace()
        self._write_settings(
            overrides={
                "doubleCheck": {"enabled": False},
                "dryRun": True,
            }
        )

        self._run_app()
        self._run_app()
        self._assert_not_processed()

    def test_double_check_label_removed_when_namespace_becomes_non_empty(self):
        """Double-check label should be cleared once a workload appears."""
        self._create_namespace()
        self._write_settings()

        self._run_app()
        self._assert_label_value("True")

        self._create_config_map()
        self._run_app()
        self._assert_not_processed()

    def test_namespace_younger_than_age_threshold_is_skipped(self):
        """Namespaces newer than ageGreaterThan should remain untouched."""
        self._create_namespace()
        self._write_settings(
            overrides={
                "ageGreaterThan": 3600,
                "doubleCheck": {"enabled": False},
            }
        )

        self._run_app()
        self._assert_not_processed()

        self._write_settings(
            overrides={
                "ageGreaterThan": 0,
                "doubleCheck": {"enabled": False},
            }
        )
        self._run_app()
        self._wait_for_namespace_absent()

    def test_resources_ignored_allow_namespace_deletion(self):
        """Resources matching resourcesIgnored should not block deletion."""
        self._create_namespace()
        ignored_name = "ignored-config"
        self._create_config_map(name=ignored_name)
        custom_ignored = copy.deepcopy(DEFAULT_RESOURCES_IGNORED)
        custom_ignored.append(
            {"apiGroup": "", "kind": "ConfigMap", "name": f"^{ignored_name}$"}
        )
        self._write_settings(
            overrides={
                "doubleCheck": {"enabled": False},
                "resourcesIgnored": custom_ignored,
            }
        )

        self._run_app()
        self._wait_for_namespace_absent()

    def test_resources_not_in_considered_treated_as_empty(self):
        """resourcesConsidered should act as a whitelist."""
        self._create_namespace()
        self._create_config_map()
        self._write_settings(
            overrides={
                "doubleCheck": {"enabled": False},
                "resourcesConsidered": [
                    {"apiGroup": "", "kind": "ConfigMap", "name": r"^matching-only$"}
                ],
            }
        )

        self._run_app()
        self._wait_for_namespace_absent()

    def test_dry_run_with_double_check_marks_without_deleting(self):
        """Dry run preserves namespace even after second pass with deletion mark."""
        self._create_namespace()
        self._write_settings(overrides={"dryRun": True})

        self._run_app()
        self._assert_label_value("True")

        self._run_app()
        self._assert_label_value("True")
        self._assert_namespace_exists()

    def test_api_resources_ignored_skip_kind(self):
        """apiResourcesIgnored should skip entire kinds when matching."""
        self._create_namespace()
        self._create_config_map()
        api_resources_ignored = copy.deepcopy(DEFAULT_API_RESOURCES_IGNORED)
        api_resources_ignored.append({"apiGroup": "", "kind": r"^ConfigMap$"})
        self._write_settings(
            overrides={
                "doubleCheck": {"enabled": False},
                "apiResourcesIgnored": api_resources_ignored,
            }
        )

        self._run_app()
        self._wait_for_namespace_absent()

    def test_api_resources_considered_whitelist(self):
        """apiResourcesConsidered should act as a whitelist."""
        self._create_namespace()
        self._create_config_map()
        self._write_settings(
            overrides={
                "doubleCheck": {"enabled": False},
                "apiResourcesConsidered": [
                    {"apiGroup": "apps", "kind": r"^Deployment$"}
                ],
            }
        )

        self._run_app()
        self._wait_for_namespace_absent()

    def test_custom_double_check_label_respected(self):
        """Custom double-check label name should be applied."""
        self._create_namespace()
        custom_label = "custom/remove"
        self._write_settings(
            overrides={
                "doubleCheck": {
                    "enabled": True,
                    "label": custom_label,
                }
            }
        )

        self._run_app()
        self._assert_label_value("True", label=custom_label)
        self._assert_not_processed(label=DOUBLE_CHECK_LABEL)

    def test_double_check_disabled_deletes_immediately(self):
        """Double-check disabled should remove empty namespaces on first run."""
        self._create_namespace()
        self._write_settings(overrides={"doubleCheck": {"enabled": False}})

        self._run_app()
        self._wait_for_namespace_absent()

    def test_filter_consider_all_when_no_filters_configured(self):
        """Empty filters should still process the namespace."""
        self._create_namespace()
        self._write_settings(
            overrides={
                "namespacesIgnored": [],
                "namespacesConsidered": [],
                "doubleCheck": {"enabled": False},
            }
        )

        self._run_app()
        self._wait_for_namespace_absent()

    def test_filter_ignore_overrides_consider(self):
        """Ignore list takes precedence over consider list."""
        self._create_namespace()
        pattern = f"^{self.namespace}$"
        self._write_settings(
            overrides={
                "namespacesIgnored": [pattern],
                "namespacesConsidered": [pattern],
            }
        )

        self._run_app()
        self._assert_not_processed()

    def test_filter_considered_only_targets_matches(self):
        """Only namespaces matching namespacesConsidered should be processed."""
        allowed = self._create_namespace(
            name=self._unique_namespace_name(prefix="allow")
        )
        blocked = self._create_namespace(
            name=self._unique_namespace_name(prefix="block")
        )
        self._write_settings(
            overrides={
                "namespacesIgnored": [],
                "namespacesConsidered": [r"^allow-.*$"],
                "doubleCheck": {"enabled": False},
            }
        )

        self._run_app()
        self._wait_for_namespace_absent(namespace=allowed)

        self._assert_not_processed(namespace=blocked)

    def test_filter_ignore_only_skips_matches(self):
        """Empty namespacesConsidered still respects namespacesIgnored."""
        keeper = self._create_namespace(name=self._unique_namespace_name(prefix="keep"))
        skipper = self._create_namespace(
            name=self._unique_namespace_name(prefix="skip")
        )
        pattern = r"^skip-.*$"
        self._write_settings(
            overrides={
                "namespacesIgnored": [pattern],
                "namespacesConsidered": [],
                "doubleCheck": {"enabled": False},
            }
        )

        self._run_app()
        self._assert_not_processed(namespace=skipper)
        self._wait_for_namespace_absent(namespace=keeper)

    def test_non_active_namespace_is_skipped(self):
        """Namespaces not in Active phase must not be processed."""
        namespace = self._create_namespace(
            name=self._unique_namespace_name(prefix="terminating"),
            finalizers=["cleanup/remove"],
        )
        self._write_settings()

        self.core_v1.delete_namespace(namespace)
        self._wait_for_namespace_phase(namespace, phase="Terminating")

        try:
            self._run_app()
            ns_obj = self.core_v1.read_namespace(namespace)
            labels = ns_obj.metadata.labels or {}
            self.assertNotIn(DOUBLE_CHECK_LABEL, labels)
        finally:
            self._clear_namespace_finalizers(namespace)
            try:
                self.core_v1.delete_namespace(namespace)
            except ApiException as exc:
                if exc.status not in (404, 409):
                    raise
            self._wait_for_namespace_absent(namespace)

    def _unique_namespace_name(self, prefix: str = "e2e-remove-empty-ns"):
        return f"{prefix}-{uuid.uuid4().hex[:8]}"

    def _create_namespace(
        self, name: str | None = None, finalizers: list[str] | None = None
    ):
        namespace = name or self.namespace
        metadata = client.V1ObjectMeta(name=namespace)
        if finalizers:
            metadata.finalizers = finalizers
        ns_obj = client.V1Namespace(metadata=metadata)
        self.core_v1.create_namespace(ns_obj)
        self.created_namespaces.add(namespace)
        return namespace

    def _create_config_map(self, namespace: str | None = None, name: str | None = None):
        target = namespace or self.namespace
        cm_name = name or f"workload-{uuid.uuid4().hex[:6]}"
        config_map = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name=cm_name),
            data={"app": "present"},
        )
        self.core_v1.create_namespaced_config_map(namespace=target, body=config_map)

    def _write_settings(self, overrides: dict | None = None):
        settings = {
            "namespacesConsidered": [f"^{self.namespace}$"],
            "namespacesIgnored": [],
            "ageGreaterThan": 0,
            "doubleCheck": {"enabled": True, "label": DOUBLE_CHECK_LABEL},
            "resourcesConsidered": [],
            "resourcesIgnored": DEFAULT_RESOURCES_IGNORED,
            "apiResourcesConsidered": [],
            "apiResourcesIgnored": DEFAULT_API_RESOURCES_IGNORED,
            "dryRun": False,
        }
        if overrides:
            settings = self._deep_merge(settings, overrides)

        with open(self.settings_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(settings, fh)

    def _run_app(self):
        cmd = [
            sys.executable,
            str(APP_PATH),
            "-c",
            str(self.settings_path),
        ]
        if not VERBOSE_TEST_RUN:
            cmd.append("-q")
        subprocess.run(cmd, cwd=REPO_ROOT, check=True)

    def _assert_label_value(
        self,
        expected: str,
        namespace: str | None = None,
        label: str = DOUBLE_CHECK_LABEL,
    ):
        name = namespace or self.namespace
        ns_obj = self.core_v1.read_namespace(name)
        labels = ns_obj.metadata.labels or {}
        self.assertEqual(
            labels.get(label),
            expected,
            "Double-check label not applied as expected",
        )

    def _assert_not_processed(
        self, namespace: str | None = None, label: str = DOUBLE_CHECK_LABEL
    ):
        name = namespace or self.namespace
        ns_obj = self.core_v1.read_namespace(name)
        labels = ns_obj.metadata.labels or {}
        self.assertNotIn(label, labels)
        self.assertIsNone(
            ns_obj.metadata.deletion_timestamp,
            f"Namespace {name} should not have been flagged for deletion",
        )

    def _assert_namespace_exists(self, namespace: str | None = None):
        name = namespace or self.namespace
        ns_obj = self.core_v1.read_namespace(name)
        self.assertIsNone(
            ns_obj.metadata.deletion_timestamp,
            f"Namespace {name} should still be active",
        )

    def _wait_for_namespace_absent(
        self, namespace: str | None = None, timeout: int = 120
    ):
        name = namespace or self.namespace
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.core_v1.read_namespace(name)
            except ApiException as exc:
                if exc.status == 404:
                    return
                raise
            time.sleep(2)
        raise AssertionError(f"Namespace {name} still exists after timeout")

    def _wait_for_namespace_phase(
        self, namespace: str, phase: str, timeout: int = 60
    ) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            ns_obj = self.core_v1.read_namespace(namespace)
            if ns_obj.status.phase == phase:
                return
            time.sleep(2)
        raise AssertionError(
            f"Namespace {namespace} did not reach phase {phase} within timeout"
        )

    def _clear_namespace_finalizers(self, namespace: str) -> None:
        meta = client.V1ObjectMeta(name=namespace, finalizers=[])
        body = client.V1Namespace(metadata=meta)
        try:
            self.core_v1.replace_namespace_finalize(namespace, body)
        except ApiException as exc:
            if exc.status not in (404, 409):
                raise

    def _deep_merge(self, base: dict, overrides: dict):
        merged = copy.deepcopy(base)
        for key, value in overrides.items():
            if (
                key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                merged[key] = self._deep_merge(merged[key], value)
            else:
                merged[key] = copy.deepcopy(value)
        return merged


if __name__ == "__main__":
    unittest.main()
