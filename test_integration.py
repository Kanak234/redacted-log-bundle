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


def test_mixed_log_line_keeps_timestamp_and_join():
    # Regression: stock entities masked the timestamp as DATE_TIME and hashed
    # "user=<email>" as one value, so the same address on another line got a
    # different token. Both must hold now.
    from bundle import pii, render

    text = (
        "2026-11-21 10:02:11 INFO user=asha@example.com pan=ABCDE1234F aadhaar=2345 6789 0123\n"
        "2026-11-21 10:03:40 ERROR callback failed for asha@example.com"
    )
    first, second = render(text, list(pii(text)), bytes(32))[0].split("\n")
    assert first.startswith("2026-11-21 10:02:11 INFO user=[R-")
    assert second.startswith("2026-11-21 10:03:40 ERROR")
    email_token = re.search(r"user=(\[R-[0-9a-f]{32}\])", first)[1]
    assert second.endswith(email_token)  # same address -> same token
    assert "ABCDE1234F" not in first and "6789" not in first
