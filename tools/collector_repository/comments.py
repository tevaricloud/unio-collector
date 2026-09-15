"""Syntax-aware comment spans for the closed public publication formats."""

from __future__ import annotations

import ast
import io
import re
import tokenize
import tomllib
from typing import TYPE_CHECKING

import yaml

from tools.collector_repository.naming import repository_text
from tools.collector_repository.paths import regular_file, repository_files, require

if TYPE_CHECKING:
    from pathlib import Path

_NATIVE_LOCK_TARGETS = ("windows-x86_64", "linux-x86_64", "macos-x86_64", "macos-arm64")
_NATIVE_LOCK_PATHS = {f"requirements/native-{target}.lock": target for target in _NATIVE_LOCK_TARGETS}
_NATIVE_LOCK_HEADER_LINES = 3


class PublicCommentPolicy:
    """Remove prose while retaining syntactically controlled tooling directives."""

    def spans(self, name: str, text: str) -> list[tuple[int, int]]:
        """Report syntax failures without including source or configuration contents."""
        try:
            return self._spans(name, text)
        except (SyntaxError, tokenize.TokenError, yaml.YAMLError, tomllib.TOMLDecodeError):
            message = f"Invalid public comment syntax: {name}."
            raise ValueError(message) from None

    def _spans(self, name: str, text: str) -> list[tuple[int, int]]:
        """Fail closed on unsupported executable formats and invalid syntax."""
        offsets = [0]
        for line in text.splitlines(keepends=True):
            offsets.append(offsets[-1] + len(line))
        if name.endswith((".py", ".pyi")):
            return [(start, end) for start, end, _replacement in self._python(name, text)]
        if name.endswith((".yaml", ".yml")):
            yaml.safe_load(text)
            literals = [(token.start_mark.index, token.end_mark.index) for token in yaml.scan(text) if isinstance(token, yaml.tokens.ScalarToken)]
            return self._hashes(text, literals)
        if name.endswith(".toml"):
            tomllib.loads(text)
            return self._toml(text)
        if name.endswith(".md"):
            return self._markdown(text)
        if name.startswith("requirements/") and name.endswith((".lock", ".txt")):
            return self._requirements(name, text)
        if name in {".gitignore", ".gitattributes"}:
            return [
                (offsets[index] + len(line) - len(line.lstrip()), offsets[index] + len(line.rstrip("\r\n")))
                for index, line in enumerate(text.splitlines(keepends=True))
                if (line.startswith("#") if name == ".gitignore" else line.lstrip().startswith("#"))
            ]
        require(name.endswith(".json") or name in {"LICENSE", "THIRD_PARTY_NOTICES"}, f"Unsupported public comment format: {name}.")
        return []

    def strip(self, name: str, text: str) -> str:
        """Preserve Python positions; remove non-Python comments without whitespace residue."""
        original = text
        python = name.endswith((".py", ".pyi"))
        edits = self._python(name, text) if python else [(start, end, "") for start, end in self.spans(name, text)]
        for start, end, replacement in reversed(edits):
            edit_start, edit_end = start, end
            if python:
                padding = "".join(character if character in "\r\n" else " " for character in text[start + len(replacement) : end])
            else:
                line_end = text.find("\n", end)
                line_end = len(text) if line_end < 0 else line_end
                if not text[end:line_end].strip(" \t\r"):
                    edit_end = line_end
                    edit_start = len(text[:start].rstrip(" \t"))
                elif "\n" in text[start:end]:
                    line_start = text.rfind("\n", 0, start) + 1
                    if not text[line_start:start].strip(" \t"):
                        edit_start = line_start
                line_start = text.rfind("\n", 0, start) + 1
                if not text[end:].strip(" \t\r\n") and not text[line_start:start].strip(" \t"):
                    edit_start, edit_end = line_start, len(text)
                    padding = ""
                else:
                    padding = "".join(character for character in text[edit_start:edit_end] if character in "\r\n")
            text = text[:edit_start] + replacement + padding + text[edit_end:]
        if name.endswith((".py", ".pyi")):
            require(ast.dump(ast.parse(original)) == ast.dump(ast.parse(text)), f"Public comment removal changed Python semantics: {name}.")
            compile(text, name, "exec")
        elif name.endswith((".yaml", ".yml")):
            require(yaml.safe_load(original) == yaml.safe_load(text), f"Public comment removal changed YAML values: {name}.")
        elif name.endswith(".toml"):
            require(tomllib.loads(original) == tomllib.loads(text), f"Public comment removal changed TOML values: {name}.")
        require(not self.spans(name, text), f"Public comment removal incomplete: {name}.")
        return text

    def _python(self, name: str, text: str) -> list[tuple[int, int, str]]:
        ast.parse(text, filename=name)
        offsets = [0]
        for line in text.splitlines(keepends=True):
            offsets.append(offsets[-1] + len(line))
        edits = []
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type != tokenize.COMMENT:
                continue
            try:
                directive = self._directive(token.string)
            except ValueError:
                message = f"Invalid public tooling directive: {name}:{token.start[0]}."
                raise ValueError(message) from None
            if directive == token.string.rstrip():
                continue
            start = offsets[token.start[0] - 1] + token.start[1]
            end = offsets[token.end[0] - 1] + token.end[1]
            edits.append((start, end, directive or ""))
        return edits

    def _directive(self, comment: str) -> str | None:
        """Recognize tool grammar rather than allowlisting explanatory comments."""
        if re.match(r"# pragma: no cover\b", comment):
            nested = comment.find("#", 1)
            directive = self._directive(comment[nested:]) if nested >= 0 else None
            return "# pragma: no cover" + ("  " + directive if directive else "")
        patterns = (
            r"#\s*(?:ruff:\s*)?noqa\b(?:\s*:\s*[A-Z]+\d+(?:\s*,\s*[A-Z]+\d+)*)?",
            r"#\s*type:\s*ignore\b(?:\[[a-zA-Z0-9_, -]+\])?",
            r"#\s*pyright:\s*ignore\b(?:\[[a-zA-Z0-9_, ]+\])?",
            r"#\s*pyright:\s*report[A-Za-z]+=(?:true|false)\b",
            r"#\s*fmt:\s*(?:off|on|skip)\b",
            r"#\s*isort:\s*(?:skip_file|skip|off|on)\b",
        )
        for pattern in patterns:
            match = re.match(pattern, comment)
            if match:
                remainder = comment[match.end() :]
                require(not remainder or remainder[0].isspace(), "Malformed public tooling directive.")
                return match.group().rstrip()
        require(not re.match(r"#\s*(?:ruff|type|pyright|fmt|isort|pylint|mypy)\s*:", comment), "Unsupported public tooling directive.")

        return None

    def validate(self, root: Path) -> None:
        """Check the complete public tree, reporting paths and locations only."""
        for name in repository_files(root):
            text = repository_text(regular_file(root, name))
            if text is None:
                continue
            spans = self.spans(name, text)
            if spans:
                line = text.count("\n", 0, spans[0][0]) + 1
                message = f"Public comment remains: {name}:{line}."
                raise ValueError(message)

    def _hashes(self, text: str, literals: list[tuple[int, int]]) -> list[tuple[int, int]]:
        spans = []
        for index, character in enumerate(text):
            if character != "#" or (index and not text[index - 1].isspace()) or any(start <= index < end for start, end in literals):
                continue
            end = text.find("\n", index)
            spans.append((index, len(text) if end == -1 else end))
        return spans

    def _requirements(self, name: str, text: str) -> list[tuple[int, int]]:
        """Recognize whitespace-delimited comments outside marker strings and URLs."""
        spans = []
        protected_end = self._native_lock_metadata_end(name, text)
        index = 0
        quote = ""
        while index < len(text):
            character = text[index]
            if character == "\\":
                index += 2
                continue
            if quote:
                if character == quote:
                    quote = ""
            elif character in {"'", '"'}:
                quote = character
            elif character == "#" and index >= protected_end and (not index or text[index - 1].isspace()):
                end = text.find("\n", index)
                end = len(text) if end == -1 else end
                spans.append((index, end))
                index = end
                continue
            index += 1
        require(not quote, "Unterminated requirements marker string.")
        return spans

    def _native_lock_metadata_end(self, name: str, text: str) -> int:
        """Protect only the canonical machine-readable public native-lock header."""
        target = _NATIVE_LOCK_PATHS.get(name)
        if target is None:
            return 0
        lines = text.splitlines(keepends=True)
        expected = (
            f"# Unio Collector native hash lock: {target}",
            "# Generated with Python 3.12.10 and pip-tools 7.6.1.",
            "# Inputs: unio-collector runtime dependencies and active target-native build dependencies.",
        )
        actual = tuple(line.rstrip("\r\n") for line in lines[:_NATIVE_LOCK_HEADER_LINES])
        require(
            len(lines) >= _NATIVE_LOCK_HEADER_LINES and actual == expected and lines[_NATIVE_LOCK_HEADER_LINES - 1].endswith("\n"),
            f"Invalid public native lock metadata: {name}.",
        )
        return sum(len(line) for line in lines[:_NATIVE_LOCK_HEADER_LINES])

    def _toml(self, text: str) -> list[tuple[int, int]]:
        literals = []
        index = 0
        while index < len(text):
            if text[index] == "#":
                end = text.find("\n", index)
                index = len(text) if end == -1 else end
            elif text[index] in {"'", '"'}:
                start = index
                quote = text[index]
                delimiter = quote * 3 if text.startswith(quote * 3, index) else quote
                index += len(delimiter)
                while index < len(text):
                    if quote == '"' and text[index] == "\\":
                        index += 2
                    elif text.startswith(delimiter, index):
                        index += len(delimiter)

                        if delimiter == quote * 3:
                            while index < len(text) and text[index] == quote:
                                index += 1
                        break
                    else:
                        index += 1
                literals.append((start, index))
            else:
                index += 1
        return [
            (index, len(text) if text.find("\n", index) == -1 else text.find("\n", index))
            for index, character in enumerate(text)
            if character == "#" and not any(start <= index < end for start, end in literals)
        ]

    def _markdown(self, text: str) -> list[tuple[int, int]]:
        spans = []
        fence = ""
        offset = 0
        lines = text.splitlines(keepends=True)
        literals = self._code_spans(text)
        for line in lines:
            marker = re.match(r"\s{0,3}(`{3,}|~{3,})", line)
            if marker:
                value = marker.group(1)
                if not fence:
                    fence = value
                elif value[0] == fence[0] and len(value) >= len(fence):
                    fence = ""
            elif not fence:
                start = line.find("<!--")
                while start >= 0:
                    absolute = offset + start
                    if any(begin <= absolute < end for begin, end in literals) or any(begin <= absolute < end for begin, end in spans):
                        start = line.find("<!--", start + 4)
                        continue
                    end = text.find("-->", absolute + 4)
                    require(end >= 0, "Unterminated hidden Markdown comment.")
                    spans.append((absolute, end + 3))
                    start = line.find("<!--", start + 4)
            offset += len(line)
        return spans

    def _code_spans(self, text: str) -> list[tuple[int, int]]:
        """Protect Markdown inline code with matching backtick delimiter runs."""
        markers = list(re.finditer(r"`+", text))
        spans = []
        index = 0
        while index < len(markers):
            opening = markers[index]
            if opening.start() and text[opening.start() - 1] == "\\":
                index += 1
                continue
            closing = next((candidate for candidate in range(index + 1, len(markers)) if markers[candidate].group() == opening.group()), None)
            if closing is None:
                index += 1
            else:
                spans.append((opening.start(), markers[closing].end()))
                index = closing + 1
        return spans
