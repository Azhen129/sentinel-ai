import json

import pytest

from scripts.generate_notices import NoticeError, VICTORY_LICENSE, VICTORY_LICENSE_URL, create_notices


def fixture(frontend, *, name="example-runtime", version="1.0.0", installed_version="1.0.0", license_text="MIT\nCopyright Example Author\nPermission example."):
    frontend.mkdir()
    lock = {"lockfileVersion": 3, "packages": {"": {},
        f"node_modules/{name}": {"version": version, "license": "MIT", "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"},
        "node_modules/build-only": {"version": "2.0.0", "license": "MPL-2.0", "dev": True}}}
    (frontend / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    package = frontend / "node_modules" / name
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": name, "version": installed_version}), encoding="utf-8")
    if license_text:
        (package / "LICENSE").write_text(license_text, encoding="utf-8")
    return lock, package


def test_complete_production_graph_nested_licenses_and_determinism(tmp_path):
    frontend = tmp_path / "frontend"
    _, package = fixture(frontend)
    vendored = package / "vendor/nested"
    vendored.mkdir(parents=True)
    (vendored / "NOTICE.txt").write_text("Actual nested vendor attribution", encoding="utf-8")
    text = create_notices(frontend)
    assert text == create_notices(frontend)
    assert "example-runtime@1.0.0" in text
    assert "Copyright Example Author" in text
    assert "Actual nested vendor attribution" in text
    assert "build-only@" not in text
    assert str(tmp_path) not in text
    assert "Production dependency entries: 1" in text


def test_version_mismatch_fails_instead_of_publishing_wrong_attribution(tmp_path):
    frontend = tmp_path / "frontend"
    fixture(frontend, installed_version="2.0.0")
    with pytest.raises(NoticeError, match="differs from lock"):
        create_notices(frontend)


def test_missing_license_needs_explicit_review(tmp_path):
    frontend = tmp_path / "frontend"
    fixture(frontend, license_text="")
    with pytest.raises(NoticeError, match="No packaged license"):
        create_notices(frontend)


def test_matching_upstream_victory_fallback_keeps_own_and_vendored_notices(tmp_path):
    frontend = tmp_path / "frontend"
    lock, package = fixture(frontend, name="victory-vendor", version="36.9.2", installed_version="36.9.2")
    lock["packages"]["node_modules/victory-vendor"] = {"version": "36.9.2", "license": "MIT AND ISC", "resolved": "https://registry.npmjs.org/victory-vendor/-/victory-vendor-36.9.2.tgz"}
    (frontend / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    text = create_notices(frontend)
    assert VICTORY_LICENSE.rstrip() in text
    assert VICTORY_LICENSE_URL in text
    assert "Copyright Example Author" in text
    lock["packages"]["node_modules/victory-vendor"]["version"] = "37.0.0"
    (frontend / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    (package / "package.json").write_text(json.dumps({"name": "victory-vendor", "version": "37.0.0"}), encoding="utf-8")
    with pytest.raises(NoticeError, match="new version"):
        create_notices(frontend)
