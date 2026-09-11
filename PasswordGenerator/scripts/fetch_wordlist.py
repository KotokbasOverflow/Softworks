#!/usr/bin/env python3
"""Regenerate src/words.rs from EFF's upstream wordlist.

Usage (run from the PasswordGenerator directory):
    python3 scripts/fetch_wordlist.py

Downloads EFF `eff_large_wordlist.txt`, verifies it (7776 `DICE WORD` lines),
and rewrites `src/words.rs` with the words embedded verbatim in upstream
order. The output must be byte-identical to the committed file unless
upstream changed — in that case update the SHA-256 in `src/words.rs`,
`tests/wordlist.rs`, and `README.md`, and call it out in the PR.

Stdlib only.
"""

import hashlib
import sys
import urllib.request
from pathlib import Path

URL = "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt"
EXPECTED_COUNT = 7776

HEADER = """//! EFF large wordlist for Diceware passphrases (7776 words, 6^5).
//!
//! Source: Electronic Frontier Foundation, "EFF's New Wordlists for Random
//! Passphrases" — file `eff_large_wordlist.txt` from <https://www.eff.org/dice>.
//! EFF site content (including the wordlists) is released under Creative
//! Commons Attribution (CC BY); see <https://www.eff.org/copyright>.
//! Words are embedded verbatim and in upstream order (verified against the
//! file downloaded 2026-09-11).
//!
//! Integrity: SHA-256 over UTF-8 bytes of the words joined with `\\n` plus a
//! trailing newline must equal:
//! `6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522`
//! (see `tests/wordlist.rs`).
//!
//! Note: 4 of the 7776 words contain a hyphen
//! (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`). With the default `-`
//! separator a passphrase may therefore contain extra `-` characters;
//! use another separator if you split on it.
"""


def main() -> int:
    here = Path(__file__).resolve().parent.parent
    out_path = here / "src" / "words.rs"

    print(f"Downloading {URL} ...")
    with urllib.request.urlopen(URL, timeout=60) as resp:
        raw = resp.read().decode("utf-8")

    words = []
    for lineno, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2 or not parts[0].isdigit():
            print(f"Unexpected line {lineno}: {line!r}", file=sys.stderr)
            return 1
        words.append(parts[1])

    if len(words) != EXPECTED_COUNT:
        print(f"Expected {EXPECTED_COUNT} words, got {len(words)}", file=sys.stderr)
        return 1

    canonical = ("\n".join(words) + "\n").encode("utf-8")
    print("SHA-256:", hashlib.sha256(canonical).hexdigest())

    body = "".join(f'    "{w}",\n' for w in words)
    out_path.write_text(
        HEADER + "pub const EFF_WORDS: &[&str] = &[\n" + body + "];\n",
        encoding="utf-8",
    )
    print(f"Wrote {out_path} ({len(words)} words)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
