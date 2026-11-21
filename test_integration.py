"""Exercise both installed detectors through the real local entry point."""

from pathlib import Path
import subprocess
import sys
import re


def test_offline_bundle(tmp_path):
    source = tmp_path / "support.txt"
    value = "tester@example.invalid"
    import random, string

    fake = "ghp_" + "".join(
        random.Random(624).choices(string.ascii_letters + string.digits, k=36)
    )
    source.write_text(
        value + "\n" + value + "\n" + fake + "\n<script>\n", encoding="utf8"
    )
    dest = tmp_path / "bundle"
    subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("bundle.py")),
            str(source),
            str(dest),
            str(tmp_path / "private.key"),
        ],
        check=True,
    )
    output = (dest / "redacted.txt").read_text().splitlines()
    assert output[0] == output[1] and re.fullmatch(r"\[R-[0-9a-f]{32}\]", output[0])
    assert fake not in output[2] and value not in (dest / "preview.html").read_text()
    assert "<script>" not in (dest / "preview.html").read_text()
