#!/usr/bin/env python3

"""Application that removes kubernetes empty namespaces."""

import argparse
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml
from kubernetes import client, config, dynamic
from kubernetes.client.rest import ApiException
from kubernetes.dynamic.resource import Resource, ResourceList
from rich.logging import RichHandler


@dataclass
class APIResourceRE:
    """apiGroup/kind regex to filter kinds to check for emptiness."""

    api_group: re.Pattern
    kind: re.Pattern


@dataclass
class ResourceRE:
    """apiGroup/kind/name regex to check namespace for emptiness."""

    api_group: re.Pattern
    kind: re.Pattern
    name: re.Pattern


@dataclass
class DoubleCheck:
    """Double check if namespace is empty before deletion."""

    enabled: bool = False
    label: str = "remove-empty-ns/will-remove"


@dataclass
class Settings:
    """Settings for the application."""

    namespaces_considered_re: list[re.Pattern] = field(default_factory=list)
    namespaces_ignored_re: list[re.Pattern] = field(default_factory=list)
    resources_considered_re: list[ResourceRE] = field(default_factory=list)
    resources_ignored_re: list[ResourceRE] = field(default_factory=list)
    api_resources: list[Resource] = field(default_factory=list)
    age_greater_than: int = 0
    double_check: DoubleCheck = field(default_factory=DoubleCheck)
    dry_run: bool = False

    @classmethod
    def from_file(
        cls,
        settings_file: str,
        dynamic_client: dynamic.DynamicClient,
        logger: logging.Logger,
    ) -> "Settings":
        """Load settings from a YAML file."""
        if not settings_file:
            logger.info("No settings file provided, using default settings")
            return cls()

        try:
            config_data = yaml.safe_load(
                Path(settings_file).read_text(encoding="utf-8")
            )
        except (OSError, yaml.YAMLError) as e:
            logger.error("Failed to load settings file %s: %s", settings_file, e)
            raise

        settings = cls()
        settings._load_regex_patterns(config_data)
        settings._load_api_resources(config_data, dynamic_client, logger)
        settings._load_other_settings(config_data)

        logger.debug("Loaded settings: %s", settings)
        return settings

    def _load_other_settings(self, config_data: dict) -> None:
        """Load non-regex settings."""
        self.age_greater_than = config_data.get("ageGreaterThan", 0)
        self.dry_run = config_data.get("dryRun", False)

        if double_check_data := config_data.get("doubleCheck"):
            self.double_check = DoubleCheck(
                enabled=double_check_data.get("enabled", False),
                label=double_check_data.get("label", "remove-empty-ns/will-remove"),
            )

    def _load_regex_patterns(self, config_data: dict) -> None:
        """Compile regex patterns from configuration."""
        self.namespaces_considered_re = [
            re.compile(pattern)
            for pattern in config_data.get("namespacesConsidered", [])
        ]
        self.namespaces_ignored_re = [
            re.compile(pattern) for pattern in config_data.get("namespacesIgnored", [])
        ]

        self.resources_considered_re = [
            ResourceRE(
                api_group=re.compile(res["apiGroup"]),
                kind=re.compile(res["kind"]),
                name=re.compile(res["name"]),
            )
            for res in config_data.get("resourcesConsidered", [])
        ]
        self.resources_ignored_re = [
            ResourceRE(
                api_group=re.compile(res["apiGroup"]),
                kind=re.compile(res["kind"]),
                name=re.compile(res["name"]),
            )
            for res in config_data.get("resourcesIgnored", [])
        ]

    def _load_api_resources(
        self,
        config_data: dict,
        dynamic_client: dynamic.DynamicClient,
        logger: logging.Logger,
    ) -> None:
        """Load and filter API resources to check for emptiness."""
        api_resources_considered_re = self._parse_api_resource_patterns(
            config_data.get("apiResourcesConsidered", [])
        )
        api_resources_ignored_re = self._parse_api_resource_patterns(
            config_data.get("apiResourcesIgnored", [])
        )

        # Get all eligible API resources
        all_eligible = self._get_eligible_api_resources(dynamic_client, logger)

        # Filter out ignored resources
        filtered = self._filter_ignored_api_resources(
            all_eligible, api_resources_ignored_re, logger
        )

        # Apply considered filter if specified
        if api_resources_considered_re:
            self.api_resources = self._filter_considered_api_resources(
                filtered, api_resources_considered_re, logger
            )
            logger.info("Using allowlist: only specified API resources will be checked")
        else:
            self.api_resources = filtered
            logger.info("All eligible API resources will be checked (no allowlist)")

    @staticmethod
    def _parse_api_resource_patterns(patterns: list[dict]) -> list[APIResourceRE]:
        """Parse API resource patterns from configuration."""
        return [
            APIResourceRE(
                api_group=re.compile(p["apiGroup"]),
                kind=re.compile(p["kind"]),
            )
            for p in patterns
        ]

    @staticmethod
    def _is_api_resource_eligible(
        api_resource: Resource, logger: logging.Logger
    ) -> bool:
        """Check if API resource is eligible for emptiness checking."""
        # Skip ResourceList objects
        if isinstance(api_resource, ResourceList):
            logger.debug("Skipping ResourceList: %s", api_resource.kind)
            return False

        # Must support list verb
        if not api_resource.verbs or "list" not in api_resource.verbs:
            logger.debug(
                "Skipping %s: missing 'list' verb (verbs=%s)",
                api_resource.kind,
                api_resource.verbs,
            )
            return False

        # Must be namespaced
        if not api_resource.namespaced:
            logger.debug("Skipping %s: not namespaced", api_resource.kind)
            return False

        return True

    def _get_eligible_api_resources(
        self, dynamic_client: dynamic.DynamicClient, logger: logging.Logger
    ) -> list[Resource]:
        """Get all eligible API resources from the cluster."""
        eligible = []
        for api_resource_list in dynamic_client.resources:
            for api_resource in api_resource_list:
                if self._is_api_resource_eligible(api_resource, logger):
                    eligible.append(api_resource)
        return eligible

    @staticmethod
    def _matches_api_resource_pattern(
        api_resource: Resource, pattern: APIResourceRE
    ) -> bool:
        """Check if API resource matches a pattern."""
        return bool(
            re.match(pattern.kind, api_resource.kind)
            and re.match(pattern.api_group, api_resource.group or "")
        )

    def _filter_ignored_api_resources(
        self,
        api_resources: list[Resource],
        ignored_patterns: list[APIResourceRE],
        logger: logging.Logger,
    ) -> list[Resource]:
        """Remove ignored API resources."""
        if not ignored_patterns:
            return api_resources

        filtered = []
        for api_resource in api_resources:
            is_ignored = any(
                self._matches_api_resource_pattern(api_resource, pattern)
                for pattern in ignored_patterns
            )
            if is_ignored:
                logger.info(
                    "Ignoring API resource: %s/%s",
                    api_resource.group,
                    api_resource.kind,
                )
            else:
                filtered.append(api_resource)
        return filtered

    def _filter_considered_api_resources(
        self,
        api_resources: list[Resource],
        considered_patterns: list[APIResourceRE],
        logger: logging.Logger,
    ) -> list[Resource]:
        """Keep only considered API resources."""
        considered: list[Resource] = []
        seen: set[tuple[str | None, str]] = set()

        for api_resource in api_resources:
            if any(
                self._matches_api_resource_pattern(api_resource, pattern)
                for pattern in considered_patterns
            ):
                key = (api_resource.group, api_resource.kind)
                if key in seen:
                    continue
                seen.add(key)
                considered.append(api_resource)
                logger.info(
                    "Considering API resource: %s/%s",
                    api_resource.group,
                    api_resource.kind,
                )

        return considered


def is_target_namespace(
    settings: Settings,
    namespace: str,
    logger: logging.Logger,
) -> bool:
    """Check if namespace matches the target namespaces regex."""

    for pattern in settings.namespaces_ignored_re:
        if pattern.match(namespace):
            logger.info(
                "namespace=%r will be ignored by pattern.pattern=%r",
                namespace,
                pattern.pattern,
            )
            return False

    # If no considered namespaces are specified, consider all namespaces
    if not settings.namespaces_considered_re:
        logger.debug("namespace=%r will be considered by default", namespace)
        return True

    for pattern in settings.namespaces_considered_re:
        if pattern.match(namespace):
            logger.info(
                "namespace=%r will be considered by pattern.pattern=%r",
                namespace,
                pattern.pattern,
            )
            return True

    logger.info("namespace=%r will be ignored: not in considered list", namespace)
    return False


def remove_empty_ns(
    settings: Settings,
    namespace_resource: client.V1Namespace,
    core_api: client.CoreV1Api,
    logger: logging.Logger,
) -> None:
    """Process namespace: delete if empty or manage deletion marks."""
    namespace = namespace_resource.metadata.name
    meta = namespace_resource.metadata

    logger.info("Processing namespace '%s'", namespace)

    # Skip non-active namespaces
    if namespace_resource.status.phase != "Active":
        logger.info(
            "Namespace '%s' is not active (phase: %s), skipping",
            namespace,
            namespace_resource.status.phase,
        )
        return

    # Check namespace age
    if not _is_namespace_old_enough(meta, settings.age_greater_than, logger):
        return

    # Check if namespace is empty
    is_ns_empty = is_empty(namespace, settings, logger)
    labels = meta.labels or {}
    label_name = settings.double_check.label
    has_deletion_mark = labels.get(label_name) == "True"

    logger.debug(
        "Namespace '%s': empty=%s, has_deletion_mark=%s, double_check=%s",
        namespace,
        is_ns_empty,
        has_deletion_mark,
        settings.double_check.enabled,
    )

    if not settings.double_check.enabled:
        _handle_namespace_without_double_check(
            namespace, is_ns_empty, core_api, settings.dry_run, logger
        )
        return

    _handle_double_check_state(
        namespace=namespace,
        metadata=meta,
        is_namespace_empty=is_ns_empty,
        has_deletion_mark=has_deletion_mark,
        label=label_name,
        core_api=core_api,
        dry_run=settings.dry_run,
        logger=logger,
    )


def _is_namespace_old_enough(
    meta: client.V1ObjectMeta, age_threshold: int, logger: logging.Logger
) -> bool:
    """Check if namespace is old enough to be processed."""
    if age_threshold <= 0:
        return True

    if not meta.creation_timestamp:
        logger.warning("Namespace %s has no creation timestamp, skipping", meta.name)
        return False

    now = datetime.now(timezone.utc)
    creation_ts = meta.creation_timestamp
    if creation_ts.tzinfo is None:
        creation_ts = creation_ts.replace(tzinfo=timezone.utc)

    age_seconds = (now - creation_ts).total_seconds()
    if age_seconds < age_threshold:
        logger.info(
            "Namespace '%s' is too young (%.0fs < %ss), skipping",
            meta.name,
            age_seconds,
            age_threshold,
        )
        return False

    return True


def _delete_namespace(
    namespace: str,
    core_api: client.CoreV1Api,
    dry_run: bool,
    logger: logging.Logger,
) -> None:
    """Delete a namespace."""
    if dry_run:
        logger.info("[DRY RUN] Would delete namespace '%s'", namespace)
        return

    try:
        logger.info("Deleting namespace '%s'", namespace)
        core_api.delete_namespace(name=namespace)
    except ApiException as e:
        logger.error("Failed to delete namespace '%s': %s", namespace, e.reason)
        raise


def _handle_namespace_without_double_check(
    namespace: str,
    is_namespace_empty: bool,
    core_api: client.CoreV1Api,
    dry_run: bool,
    logger: logging.Logger,
) -> None:
    """Handle namespace deletion workflow when double check is disabled."""
    if is_namespace_empty:
        _delete_namespace(namespace, core_api, dry_run, logger)
    else:
        logger.info("Namespace '%s' is not empty, skipping", namespace)


def _handle_double_check_state(
    namespace: str,
    metadata: client.V1ObjectMeta,
    is_namespace_empty: bool,
    has_deletion_mark: bool,
    label: str,
    core_api: client.CoreV1Api,
    dry_run: bool,
    logger: logging.Logger,
) -> None:
    """Handle namespace deletion workflow when double check is enabled."""
    if is_namespace_empty and has_deletion_mark:
        logger.info("Namespace '%s' has deletion mark and is still empty", namespace)
        _delete_namespace(namespace, core_api, dry_run, logger)
        return

    if is_namespace_empty:
        logger.info("Namespace '%s' is empty, adding deletion mark", namespace)
        add_will_remove_label(metadata, label, core_api, logger)
        return

    if has_deletion_mark:
        logger.info(
            "Namespace '%s' is no longer empty, removing deletion mark",
            namespace,
        )
        del_will_remove_label(metadata, label, core_api, logger)
        return

    logger.info("Namespace '%s' is not empty, skipping", namespace)


def is_empty(namespace: str, settings: Settings, logger: logging.Logger) -> bool:
    """Check if namespace does not contain any non-ignored resources."""
    logger.info("Checking if namespace '%s' is empty", namespace)

    for api_resource in settings.api_resources:
        if _namespace_has_relevant_resources(namespace, api_resource, settings, logger):
            return False

    logger.info("Namespace '%s' is empty", namespace)
    return True


def _namespace_has_relevant_resources(
    namespace: str,
    api_resource: Resource,
    settings: Settings,
    logger: logging.Logger,
) -> bool:
    """Return True if namespace still contains resources we care about."""
    logger.debug(
        "Checking %s/%s in %s",
        api_resource.group,
        api_resource.kind,
        namespace,
    )

    try:
        resource_instances = api_resource.get(namespace=namespace)
    except ApiException as e:
        logger.warning(
            "Failed to list %s/%s in %s: %s",
            api_resource.group,
            api_resource.kind,
            namespace,
            e.reason,
        )
        return False

    for resource in resource_instances.items:
        resource_name = resource.metadata.name
        logger.debug(
            "Found %s/%s/%s",
            api_resource.group,
            api_resource.kind,
            resource_name,
        )

        if _match_resource_patterns(
            settings.resources_ignored_re, api_resource, resource_name
        ):
            logger.info(
                "Ignoring resource: %s/%s/%s",
                api_resource.group,
                api_resource.kind,
                resource_name,
            )
            continue

        if _should_consider_resource(
            settings.resources_considered_re, api_resource, resource_name
        ):
            logger.info(
                "Found significant resource: %s/%s/%s",
                api_resource.group,
                api_resource.kind,
                resource_name,
            )
            return True

    return False


def _match_resource_patterns(
    patterns: list[ResourceRE],
    api_resource: Resource,
    resource_name: str,
) -> bool:
    """Return True if the api_resource/resource_name matches one of the patterns."""
    return any(
        pattern.api_group.match(api_resource.group or "")
        and pattern.kind.match(api_resource.kind)
        and pattern.name.match(resource_name)
        for pattern in patterns
    )


def _should_consider_resource(
    considered_patterns: list[ResourceRE],
    api_resource: Resource,
    resource_name: str,
) -> bool:
    """Return True when resource should block namespace deletion."""
    if not considered_patterns:
        return True
    return _match_resource_patterns(considered_patterns, api_resource, resource_name)


def add_will_remove_label(
    meta: client.V1ObjectMeta,
    label: str,
    core_api: client.CoreV1Api,
    logger: logging.Logger,
) -> None:
    """Add label to mark namespace for deletion."""
    try:
        patch = {"metadata": {"labels": {label: "True"}}}
        core_api.patch_namespace(name=meta.name, body=patch)
        logger.debug("Added label '%s=True' to namespace %s", label, meta.name)
    except ApiException as e:
        logger.error("Failed to add label to namespace %s: %s", meta.name, e.reason)
        raise


def del_will_remove_label(
    meta: client.V1ObjectMeta,
    label: str,
    core_api: client.CoreV1Api,
    logger: logging.Logger,
) -> None:
    """Remove deletion label from namespace using JSON Patch."""
    try:
        # Use JSON Patch with proper content-type header.
        # RFC 6901 JSON Pointer escaping: ~ becomes ~0, then / becomes ~1.
        escaped_label = label.replace("~", "~0").replace("/", "~1")
        patch_body = [
            {
                "op": "remove",
                "path": f"/metadata/labels/{escaped_label}",
            }
        ]

        core_api.api_client.call_api(
            resource_path=f"/api/v1/namespaces/{meta.name}",
            method="PATCH",
            body=patch_body,
            header_params={
                "Content-Type": "application/json-patch+json",
                "Accept": "application/json",
            },
            response_type="V1Namespace",
            auth_settings=["BearerToken"],
        )

        logger.debug("Removed label '%s' from namespace %s", label, meta.name)
    except ApiException as e:
        # If label doesn't exist, that's fine
        if e.status == 422:  # Unprocessable Entity
            logger.debug("Label '%s' not found on namespace %s", label, meta.name)
        else:
            logger.error(
                "Failed to remove label from namespace %s: %s", meta.name, e.reason
            )
            raise


def setup_logging(verbose: int, quiet: bool) -> logging.Logger:
    """Setup logging."""

    logger = logging.getLogger(__name__)
    logging.disable(logging.NOTSET)

    if quiet:
        logging.disable(logging.CRITICAL)
        return logger

    levels = [logging.INFO, logging.DEBUG]
    level = levels[min(verbose, len(levels) - 1)]

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)],
    )
    return logger


def setup_kubernetes(
    logger: logging.Logger,
) -> tuple[client.CoreV1Api, dynamic.DynamicClient]:
    """Setup Kubernetes client and dynamic client."""

    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster kube config")
    except config.ConfigException:
        config.load_kube_config()
        logger.info("Loaded local kube config")

    core_api = client.CoreV1Api()
    dynamic_client = dynamic.DynamicClient(client.api_client.ApiClient())
    return core_api, dynamic_client


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(
        description="Application that removes kubernetes empty namespaces."
    )

    # Boolean flags
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress logging output",
    )

    # Options with values
    # parser.add_argument(
    #     "-n", "--namespace", type=str, default="", help="Namespace to process"
    # )
    parser.add_argument("-c", "--config", required=True, help="Path to config file")

    return parser.parse_args()


def main() -> None:
    """Main function."""
    args = parse_arguments()
    logger = setup_logging(args.verbose, args.quiet)

    try:
        core_api, dynamic_client = setup_kubernetes(logger)
        settings = Settings.from_file(args.config, dynamic_client, logger)

        logger.info("Starting namespace scan")
        namespaces = core_api.list_namespace().items
        logger.info("Found %d namespaces to check", len(namespaces))

        processed_count = 0
        for namespace in namespaces:
            namespace_name = namespace.metadata.name
            logger.debug("Evaluating namespace '%s'", namespace_name)
            if is_target_namespace(settings, namespace_name, logger):
                remove_empty_ns(settings, namespace, core_api, logger)
                processed_count += 1

        logger.info("Completed: processed %d namespaces", processed_count)

    except Exception as e:
        logger.exception("Fatal error: %s", e)
        raise


if __name__ == "__main__":
    main()
