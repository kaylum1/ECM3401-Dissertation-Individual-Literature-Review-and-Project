

"""
Passive Directory Listing Security Scanner
==========================================

This script quietly probes for open directory listings on a site
and flags any “Index of” pages it finds under a handful of common
directories (backup, logs, admin, etc.).  If a listing is up, it also
peeks for files with risky extensions (.log, .sql, .bak, etc.) and
deducts points.

Score starts at 10 and drops when:
  - You see one or more open directories.
  - Sensitive file types show up in the listing.
  - Backup files turn up.

Final score is clamped between 1 and 10.

TODO:
  • Maybe detect actual filenames (not just extensions).
  • Follow redirects to catch hidden admin panels.
"""

import requests
from urllib.parse import urljoin
from typing import List, Tuple

# ——— tweak these directories and extensions as needed ———
SENSITIVE_DIRS = [
    "backup", "logs", "admin", "config", "private", "database", "server-status"
]
EXPOSED_EXTS = [
    ".log", ".sql", ".bak", ".env", ".xml", ".conf", ".json", ".yml", ".ini"
]

# ——— how many points to lose for each problem ———
DEDUCTIONS = {
    "open_directory": 3,
    "exposed_sensitive_files": 4,
    "exposed_backup_files": 5,
}


def analyze_directory_security(base_url: str) -> Tuple[int, List[str]]:
    """
    Probe a few known paths on base_url for directory listings.
    Return a tuple: (score out of 10, list of human-readable findings).
    """
    score = 10
    notes: List[str] = []
    found_dirs: List[str] = []
    found_exts: List[str] = []

    for d in SENSITIVE_DIRS:
        test_url = urljoin(base_url, d.rstrip('/') + '/')
        try:
            r = requests.get(test_url, timeout=5)
        except requests.RequestException:
            continue  # skip unreachable paths

        # Look for the classic Apache/Nginx index page
        if r.status_code == 200 and "Index of" in r.text:
            found_dirs.append(test_url)
            # scan for any of our risky file extensions
            for ext in EXPOSED_EXTS:
                if ext in r.text:
                    found_exts.append(ext)

    # Deduct for any directory listings
    if found_dirs:
        score -= DEDUCTIONS["open_directory"]
        sample = found_dirs[:3]
        suffix = "..." if len(found_dirs) > 3 else ""
        notes.append(
            f"Open dirs: {', '.join(sample)}{suffix} "
            f"(-{DEDUCTIONS['open_directory']})"
        )

    # Separate backup files from other sensitive types
    backups = [e for e in found_exts if e in (".bak", ".log")]
    sens = [e for e in found_exts if e not in backups]

    if sens:
        score -= DEDUCTIONS["exposed_sensitive_files"]
        notes.append(
            f"Sensitive files exposed: {', '.join(sorted(set(sens)))} "
            f"(-{DEDUCTIONS['exposed_sensitive_files']})"
        )

    if backups:
        score -= DEDUCTIONS["exposed_backup_files"]
        notes.append(
            f"Backup files exposed: {', '.join(sorted(set(backups)))} "
            f"(-{DEDUCTIONS['exposed_backup_files']})"
        )

    # Clamp score into [1, 10]
    score = max(1, min(10, score))

    # Wrap up with a quick summary line
    if score == 10:
        notes.append("No directory listing issues spotted.")
    elif score < 5:
        notes.append("High risk: sensitive directories or files are exposed!")
    else:
        notes.append("Moderate risk: some directory exposure detected.")

    return score, notes


# ---------------------------------------------------------------------------- #
# Simple CLI for standalone testing (does not affect server integration)
# ---------------------------------------------------------------------------- #
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Passive directory listing scan (score 1–10)"
    )
    parser.add_argument(
        "-u", "--url", required=True,
        help="Base URL to test (include http:// or https://)"
    )
    args = parser.parse_args()

    sc, findings = analyze_directory_security(args.url)
    print("\n--- Directory Listing Scan Results ---")
    for line in findings:
        print(" *", line)
    print(f"\nFinal Score: {sc}/10")
    if sc < 5:
        print(" ritical: fix directory listings immediately!")
    elif sc < 8:
        print(" Warning: some exposures detected, consider hardening.")
    else:
        print("All clear for directory listings.")

