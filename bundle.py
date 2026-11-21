"""Offline plain-text redaction. Offsets are Python character indices."""

import argparse
import collections
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

FORMATS = {
    "AADHAAR_FORMAT": r"(?<!\w)[2-9]\d{3}([ -]?)\d{4}\1\d{4}(?!\w)",
    "PAN_FORMAT": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    "INDIAN_PHONE": r"(?<![\w+])(?:\+91[ -]?)?[6-9][0-9]{9}(?!\w)",
}


def india_recognizers():
    from presidio_analyzer import Pattern, PatternRecognizer

    # Use the same span representation for built-in and India-specific results.
    return [
        PatternRecognizer(supported_entity=name, patterns=[Pattern(name, regex, 0.7)])
        for name, regex in FORMATS.items()
    ]


def pii(text, india=True):
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    # Explicitly select the installed English model so first use also works offline.
    engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
    ).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=engine)
    if india:
        for recognizer in india_recognizers():
            analyzer.registry.add_recognizer(recognizer)
        from presidio_analyzer import Pattern, PatternRecognizer

        # Internal and reserved DNS suffixes are common in support logs. Recognize bare mailbox syntax.
        mailbox = Pattern("mailbox", r"(?<![\w.+-])[\w.%+-]+@[\w-]+(?:\.[\w-]+)+", 0.75)
        analyzer.registry.add_recognizer(
            PatternRecognizer(supported_entity="EMAIL_ADDRESS", patterns=[mailbox])
        )
    offset = 0
    for line in text.splitlines(keepends=True):
        # A recognizer can include trailing whitespace in a finding. Keep record delimiters intact.
        for hit in analyzer.analyze(text=line.rstrip("\r\n"), language="en"):
            yield offset + hit.start, offset + hit.end, hit.entity_type
        offset += len(line)  # Convert per-line indices to file coordinates.


def leaks(text):
    # Keep raw input and the sensitive scanner report outside the exported bundle.
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        report = root / "findings.json"
        run = subprocess.run(
            [
                "gitleaks",
                "stdin",
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--exit-code",
                "0",
                "--no-banner",
            ],
            input=text.encode(),
            cwd=root,
            capture_output=True,
        )
        if run.returncode:
            raise RuntimeError("Gitleaks failed. No bundle published.")
        for hit in json.loads(report.read_text(encoding="utf8")) or []:
            value = hit["Secret"]
            if not value or value not in text:
                raise ValueError("Cannot locate scanner finding")
            # Mask every literal occurrence, including repetitions outside the triggering context.
            for match in re.finditer(re.escape(value), text):
                yield match.start(), match.end(), "SECRET"


def render(text, hits, key):
    groups = []
    for start, end, label in sorted(hits):
        if not 0 <= start < end <= len(text):
            raise ValueError("Invalid span")
        if groups and start < groups[-1][1]:
            left, right, labels = groups[-1]
            groups[-1] = left, max(right, end), labels | {label}
        else:
            groups.append((start, end, {label}))
    # Replace the entire union so a nested or partially overlapping finding cannot expose a suffix.
    parts, counts, cursor = [], collections.Counter(), 0
    for start, end, labels in groups:
        digest = hmac.new(key, text[start:end].encode(), hashlib.sha256).hexdigest()[
            :32
        ]
        parts.extend((text[cursor:start], "[R-" + digest + "]"))
        counts["+".join(sorted(labels))] += 1
        cursor = end
    return "".join(parts) + text[cursor:], dict(counts)


def main():
    parser = argparse.ArgumentParser()
    for arg in ("input", "output", "key"):
        parser.add_argument(arg, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Choose a new output directory")
    if not args.key.exists():
        # Exclusive creation protects an existing correlation key against accidental rotation.
        with os.fdopen(
            os.open(args.key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
        ) as stream:
            stream.write(secrets.token_bytes(32))
    key = args.key.read_bytes()
    if len(key) != 32:
        parser.error("Key must contain exactly 32 bytes")
    text = args.input.read_bytes().decode("utf8")
    masked, counts = render(text, [*pii(text), *leaks(text)], key)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as temp:
        stage = Path(temp) / "bundle"
        stage.mkdir()
        (stage / "redacted.txt").write_bytes(masked.encode())
        (stage / "summary.json").write_text(json.dumps(counts, indent=2))
        (stage / "preview.html").write_text(
            '<meta charset="utf-8"><pre>' + html.escape(masked) + "</pre>",
            encoding="utf8",
        )
        stage.rename(
            args.output
        )  # Publish only complete outputs on the same filesystem.


if __name__ == "__main__":
    main()
