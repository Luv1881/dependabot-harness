"""Java adapter. `mvn dependency:tree` + `jdeps`, class-level (M10+)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from .base import EcosystemAdapter, Scope, ScopeResult

_DEV_SCOPES = {"test", "provided"}
_NS = re.compile(r"\{.*?\}")


class JavaAdapter(EcosystemAdapter):
    ecosystem = "maven"
    manifests = ("pom.xml", "build.gradle", "build.gradle.kts")

    def dev_scope_is_conclusive(self) -> bool:
        """Maven `test` and `provided` scopes are excluded from the packaged artifact by
        the build lifecycle itself."""
        return True

    def confidence_ceiling(self) -> float:
        return 0.70

    def resolve_scope(self, manifest_text: str, package: str) -> ScopeResult:
        """`package` is Maven-style `groupId:artifactId`."""
        if ":" not in package:
            return ScopeResult(Scope.UNKNOWN, None, "maven:unrecognized-coordinate")
        group_id, artifact_id = package.split(":", 1)
        try:
            root = ET.fromstring(manifest_text)
        except ET.ParseError:
            return ScopeResult(Scope.UNKNOWN, None, "pom.xml:unparsable")

        for dep in root.iter():
            if _local(dep.tag) != "dependency":
                continue
            fields = {_local(c.tag): (c.text or "").strip() for c in dep}
            if fields.get("groupId") == group_id and fields.get("artifactId") == artifact_id:
                scope = (fields.get("scope") or "compile").lower()
                return ScopeResult(
                    scope=Scope.DEVELOPMENT if scope in _DEV_SCOPES else Scope.RUNTIME,
                    is_direct=True,
                    source=f"pom.xml:dependency[scope={scope}]",
                )
        return ScopeResult(Scope.UNKNOWN, False, "pom.xml:transitive-or-absent")


def _local(tag: str) -> str:
    return _NS.sub("", tag)
