"""Compare the shipped pipeline against stock Presidio and stock Gitleaks."""

import json
import random
import re
import hashlib
import hmac
import secrets
from bundle import pii, leaks, render


def main():
    rng = random.Random(42)
    rows = []
    for i in range(12):
        # Non-issued fixtures are constructed locally. The token has no associated account.
        for category, value in [
            # Public-TLD mail (example.com is reserved by RFC 2606, so no real inbox).
            # Stock Presidio validates the TLD, so this is the fair head-to-head row.
            ("email", f"tester{i}@example.com"),
            # Internal suffixes (.invalid, .local, .corp) are common in support logs.
            # Stock Presidio rejects them; the bundle's mailbox pattern is built for them.
            ("email-internal", f"svc{i}@build.invalid"),
            ("PAN", f"ZZZZZ{i:04}Z"),
            ("Aadhaar", f"2345 0000 {i:04}"),
            ("phone", f"+91 900000{i:04}"),
            (
                "secret",
                "ghp_"
                + "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=36)),
            ),
            ("benign", f"build-step-{i}"),
        ]:
            rows.extend([(category, value)] * 2)
    rng.shuffle(rows)
    text = "\n".join(value for _, value in rows)
    key = secrets.token_bytes(32)
    stock, secret = list(pii(text, False)), list(leaks(text))
    for name, hits in [
        ("Presidio", stock),
        ("Gitleaks", secret),
        ("Bundle", list(pii(text)) + secret),
    ]:
        lines = render(text, hits, key)[0].split("\n")
        if len(lines) != len(rows):
            raise ValueError("A finding crossed benchmark records")
        scores, pairs, false = {}, {}, 0
        for (category, value), line in zip(rows, lines):
            if category == "benign":
                false += line != value
                continue
            masked = bool(re.fullmatch(r"\[R-[0-9a-f]{32}\]", line))
            scores.setdefault(category, []).append(masked)
            pairs.setdefault(value, []).append(line if masked else None)
        # A missed pair cannot get join credit merely because both raw strings survived.
        joins = sum(a is not None and a == b for a, b in pairs.values())
        print(
            json.dumps(
                dict(
                    suite="single-value",
                    detector=name,
                    recall={k: sum(v) / len(v) for k, v in scores.items()},
                    false_redactions=false,
                    preserved_pairs=joins,
                    total_pairs=len(pairs),
                )
            )
        )


def mixed_lines():
    """Realistic support-log lines: timestamp, level and several fields on ONE line.

    The single-value suite above puts one value per line, which hides two failure
    modes: a detector span that swallows the neighbouring field, and a timestamp
    that gets masked as DATE_TIME (the log then loses its timeline). This suite
    measures both, plus whether each value always turns into the SAME token.
    """
    rng = random.Random(7)
    pool = {
        "email": [f"user{i}@example.com" for i in range(6)],
        "phone": [f"+91 9{rng.randrange(10**8, 10**9)}" for _ in range(6)],
        "PAN": [f"ABCDE{1000 + i}F" for i in range(6)],
        "Aadhaar": [f"2345 {rng.randrange(1000, 9999)} {rng.randrange(1000, 9999)}" for _ in range(6)],
        "IP": [f"10.20.{i}.{rng.randrange(2, 250)}" for i in range(6)],
    }
    lines, truth = [], []
    for n in range(24):
        stamp = f"2026-11-21 10:{n:02d}:{rng.randrange(60):02d}"
        picked = {cat: rng.choice(vals) for cat, vals in pool.items()}
        lines.append(
            f"{stamp} {rng.choice(['INFO', 'WARN', 'ERROR'])} kyc-check step={n} "
            f"user={picked['email']} phone={picked['phone']} pan={picked['PAN']} "
            f"aadhaar={picked['Aadhaar']} ip={picked['IP']}"
        )
        truth.append((stamp, picked))
    text = "\n".join(lines)
    key = secrets.token_bytes(32)

    def token(value):
        # The exact placeholder a perfect detector would emit for this value alone.
        return "[R-" + hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:32] + "]"

    secret = list(leaks(text))
    for name, hits in [
        ("Presidio", list(pii(text, False))),
        ("Gitleaks", secret),
        ("Bundle", list(pii(text)) + secret),
    ]:
        out = render(text, hits, key)[0].split("\n")
        hidden, exact, kept = {}, {}, 0
        for (stamp, picked), line in zip(truth, out):
            kept += line.startswith(stamp)  # timeline survives masking
            for cat, value in picked.items():
                hidden.setdefault(cat, []).append(value not in line)
                # Exact token = masked with nothing extra glued on, so joins work.
                exact.setdefault(cat, []).append(token(value) in line)
        print(
            json.dumps(
                dict(
                    suite="mixed-lines",
                    detector=name,
                    hidden={k: round(sum(v) / len(v), 3) for k, v in hidden.items()},
                    exact_token={k: round(sum(v) / len(v), 3) for k, v in exact.items()},
                    timestamps_kept=f"{kept}/{len(lines)}",
                )
            )
        )


if __name__ == "__main__":
    main()
    mixed_lines()
