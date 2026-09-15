"""Path admission for public repositories without development-agent tooling."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tools.collector_repository.paths import relative_path, repository_files, require, unlinked

if TYPE_CHECKING:
    from pathlib import Path

_FILES = frozenset(
    {
        "agents.md",
        "agents.override.md",
        "claude.md",
        "claude.local.md",
        "gemini.md",
        ".cursorrules",
        ".cursorignore",
        ".cursorindexingignore",
        ".aider.conf.yml",
        ".aider.conf.yaml",
        ".aiderignore",
        ".aider.chat.history.md",
        ".aider.input.history",
        ".aider.model.settings.yml",
        ".aider.model.metadata.json",
        ".windsurfrules",
        ".windsurfignore",
        ".clinerules",
        ".clineignore",
        ".roorules",
        ".rooignore",
        ".continueignore",
        "codex.md",
        "copilot-instructions.md",
    }
)
_DIRECTORIES = frozenset({".codex", ".claude", ".gemini", ".cursor", ".windsurf", ".cline", ".clinerules", ".roo", ".continue"})


class PublicAssistantArtifactPolicy:
    """Reject known instruction/configuration paths without inspecting prose."""

    def validate_path(self, name: str) -> None:
        """Check portable relative paths before any publication writes."""
        parts = relative_path(name).casefold().split("/")
        prohibited = any(part in _FILES or part in _DIRECTORIES for part in parts)
        prohibited |= any(parts[index] == ".github" and parts[index + 1] in {"instructions", "agents", "prompts"} for index in range(len(parts) - 1))
        require(not prohibited, f"Prohibited public assistant artefact: {name}.")

    def validate(self, root: Path) -> None:
        """Walk all payload paths, including empty directories; skip Git metadata."""
        for name in repository_files(root):
            self.validate_path(name)
        pending = [root]
        while pending:
            directory = pending.pop()
            for child in sorted(directory.iterdir(), key=lambda path: path.name):
                if directory == root and child.name == ".git":
                    continue
                unlinked(child, boundary=root)
                self.validate_path(child.relative_to(root).as_posix())
                if child.is_dir():
                    pending.append(child)
