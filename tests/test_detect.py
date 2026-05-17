"""Tests for project type detection — verifies that detect() correctly identifies languages and tools."""
from pathlib import Path

from pipewarden.detect import detect


def test_empty_directory_detects_nothing(tmp_project: Path) -> None:
    """An empty directory should produce no labels and no detected languages."""
    d = detect(tmp_project)
    assert d.labels() == []
    assert not d.python and not d.node and not d.dotnet


def test_python_pyproject(tmp_project: Path) -> None:
    """A pyproject.toml file should trigger Python detection and set has_pyproject."""
    (tmp_project / "pyproject.toml").write_text("[project]\nname='x'\n")
    d = detect(tmp_project)
    assert d.python
    assert d.has_pyproject


def test_python_requirements(tmp_project: Path) -> None:
    """A requirements.txt file should trigger Python detection and set has_requirements."""
    (tmp_project / "requirements.txt").write_text("requests\n")
    d = detect(tmp_project)
    assert d.python
    assert d.has_requirements


def test_node_npm_default(tmp_project: Path) -> None:
    """A bare package.json with no lock file should default to npm as the package manager."""
    (tmp_project / "package.json").write_text("{}")
    d = detect(tmp_project)
    assert d.node and d.node_pm == "npm"


def test_node_pnpm_wins_over_npm(tmp_project: Path) -> None:
    """pnpm-lock.yaml should take priority over package-lock.json when both are present."""
    (tmp_project / "package.json").write_text("{}")
    (tmp_project / "pnpm-lock.yaml").write_text("")
    (tmp_project / "package-lock.json").write_text("{}")
    d = detect(tmp_project)
    assert d.node_pm == "pnpm"


def test_node_yarn(tmp_project: Path) -> None:
    """A yarn.lock file should select yarn as the Node package manager."""
    (tmp_project / "package.json").write_text("{}")
    (tmp_project / "yarn.lock").write_text("")
    d = detect(tmp_project)
    assert d.node_pm == "yarn"


def test_rust(tmp_project: Path) -> None:
    """A Cargo.toml file should trigger Rust detection."""
    (tmp_project / "Cargo.toml").write_text("[package]\nname='x'\nversion='0.1.0'\n")
    d = detect(tmp_project)
    assert d.rust


def test_go(tmp_project: Path) -> None:
    """A go.mod file should trigger Go detection."""
    (tmp_project / "go.mod").write_text("module x\n")
    d = detect(tmp_project)
    assert d.go


def test_docker_prefers_dockerfile(tmp_project: Path) -> None:
    """A Dockerfile at the project root should trigger Docker detection with the correct name."""
    (tmp_project / "Dockerfile").write_text("FROM scratch\n")
    d = detect(tmp_project)
    assert d.docker and d.dockerfile_name == "Dockerfile"


def test_containerfile(tmp_project: Path) -> None:
    """A Containerfile should also trigger Docker detection with the correct name."""
    (tmp_project / "Containerfile").write_text("FROM scratch\n")
    d = detect(tmp_project)
    assert d.docker and d.dockerfile_name == "Containerfile"


def test_dotnet_solution(tmp_project: Path) -> None:
    """A .sln file at the project root should trigger .NET detection."""
    (tmp_project / "MyApp.sln").write_text("")
    d = detect(tmp_project)
    assert d.dotnet


def test_dotnet_nested_csproj(tmp_project: Path) -> None:
    """A .csproj file in a subdirectory should trigger .NET detection."""
    sub = tmp_project / "App"
    sub.mkdir()
    (sub / "App.csproj").write_text("<Project></Project>")
    d = detect(tmp_project)
    assert d.dotnet


def test_polyglot_repo(tmp_project: Path) -> None:
    """A repo with Python, Node, and Go files should report all three in labels()."""
    (tmp_project / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_project / "package.json").write_text("{}")
    (tmp_project / "go.mod").write_text("module x\n")
    d = detect(tmp_project)
    labels = d.labels()
    assert "python" in labels
    assert any(label.startswith("node") for label in labels)
    assert "go" in labels
