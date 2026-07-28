from __future__ import annotations

from pathlib import Path

from harness.analysis.imports import ImportIndex, build_scanner


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class TestIndexSemantics:
    def test_unavailable_returns_none_not_false(self) -> None:
        index = ImportIndex.unavailable("no checkout")
        assert index.contains("anything") is None
        assert index.any_prefix("anything") is None

    def test_prefix_match_for_subpackages(self) -> None:
        index = ImportIndex(scanned=True, modules={"github.com/vuln/lib/parser"})
        assert index.any_prefix("github.com/vuln/lib") is True

    def test_absent_reports_false_when_scanned(self) -> None:
        index = ImportIndex(scanned=True, modules={"fmt"})
        assert index.any_prefix("github.com/vuln/lib") is False


class TestGoScanner:
    def test_block_and_single_imports(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "main.go",
            'package main\n\nimport (\n\t"fmt"\n\t"github.com/vuln/lib"\n)\n',
        )
        write(tmp_path, "other.go", 'package other\n\nimport "github.com/x/y"\n')
        index = build_scanner("go").scan(tmp_path)
        assert index.scanned
        assert index.any_prefix("github.com/vuln/lib") is True
        assert index.any_prefix("github.com/x/y") is True

    def test_aliased_import(self, tmp_path: Path) -> None:
        write(tmp_path, "a.go", 'package a\nimport alias "github.com/vuln/lib"\n')
        assert build_scanner("go").scan(tmp_path).any_prefix("github.com/vuln/lib") is True

    def test_vendor_is_skipped(self, tmp_path: Path) -> None:
        write(tmp_path, "vendor/dep/x.go", 'import "github.com/vuln/lib"')
        assert build_scanner("go").scan(tmp_path).any_prefix("github.com/vuln/lib") is False


class TestPythonScanner:
    def test_import_and_from_forms(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "import requests\nfrom flask import Flask\n")
        index = build_scanner("pip").scan(tmp_path)
        assert index.any_prefix("requests") is True
        assert index.any_prefix("flask") is True

    def test_dotted_import_records_root(self, tmp_path: Path) -> None:
        write(tmp_path, "a.py", "import urllib3.util.retry\n")
        assert build_scanner("pip").scan(tmp_path).any_prefix("urllib3") is True

    def test_package_name_normalized(self) -> None:
        scanner = build_scanner("pip")
        assert scanner.normalize_package("Flask-Login") == "flask_login"


class TestNpmScanner:
    def test_esm_cjs_and_dynamic(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "a.ts",
            "import x from 'lodash';\nconst y = require('minimist');\n"
            "await import('axios');\nimport 'side-effect';\n",
        )
        index = build_scanner("npm").scan(tmp_path)
        for pkg in ("lodash", "minimist", "axios", "side-effect"):
            assert index.any_prefix(pkg) is True

    def test_relative_imports_excluded(self, tmp_path: Path) -> None:
        write(tmp_path, "a.js", "import x from './local';\n")
        assert build_scanner("npm").scan(tmp_path).modules == set()

    def test_node_modules_skipped(self, tmp_path: Path) -> None:
        write(tmp_path, "node_modules/pkg/index.js", "require('lodash')")
        assert build_scanner("npm").scan(tmp_path).any_prefix("lodash") is False


class TestJavaScanner:
    def test_import_and_static_import(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "A.java",
            "import com.fasterxml.jackson.databind.ObjectMapper;\n"
            "import static org.junit.Assert.assertEquals;\n",
        )
        index = build_scanner("maven").scan(tmp_path)
        assert index.any_prefix("com.fasterxml.jackson.databind") is True

    def test_declines_package_membership(self) -> None:
        assert build_scanner("maven").supports_package_membership is False

    def test_other_scanners_support_membership(self) -> None:
        for ecosystem in ("go", "pip", "npm", "cargo"):
            assert build_scanner(ecosystem).supports_package_membership is True


class TestRustScanner:
    def test_use_and_extern_crate(self, tmp_path: Path) -> None:
        write(tmp_path, "a.rs", "use serde::Serialize;\nextern crate libc;\n")
        index = build_scanner("cargo").scan(tmp_path)
        assert index.any_prefix("serde") is True
        assert index.any_prefix("libc") is True

    def test_hyphen_crate_normalized_to_underscore(self) -> None:
        assert build_scanner("cargo").normalize_package("my-crate") == "my_crate"


class TestScannerRegistry:
    def test_unsupported_ecosystem_returns_none(self) -> None:
        assert build_scanner("cocoapods") is None

    def test_missing_directory_is_unavailable(self, tmp_path: Path) -> None:
        index = build_scanner("go").scan(tmp_path / "nope")
        assert index.scanned is False
        assert index.contains("x") is None


class TestRustInternalPaths:
    def test_crate_self_super_are_not_dependencies(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "a.rs",
            "use crate::internal::Thing;\nuse self::helper;\n"
            "use super::parent;\nuse serde::Serialize;\n",
        )
        index = build_scanner("cargo").scan(tmp_path)
        assert index.modules == {"serde"}
