#!/usr/bin/env python3
"""
LeakHawk — Local-first password audit and remediation tool.

Zero-trust architecture: your passwords never leave this machine.
The only network call is an anonymized k-anonymity hash-prefix lookup
against Have I Been Pwned (see hibp.py for details).

Usage:
    python main.py audit  passwords.csv
    python main.py audit  passwords.csv --no-hibp        (offline mode, patterns only)
    python main.py fix    passwords.csv --output new.csv --length 14
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import importer
import hibp
import pattern_detect
import entropy
import generator
import report
import exporter

import pyfiglet
from rich.progress import track
from rich.console import Console

console = Console()


def print_banner():
    ascii_art = pyfiglet.figlet_format("LeakHawk", font="small")
    console.print(f"[bold yellow]{ascii_art}[/bold yellow][dim]  sees through the disguise.[/dim]\n")


def run_audit(csv_path: str, use_hibp: bool = True):
    console.print(f"[bold cyan]Loading[/bold cyan] {csv_path}...")
    entries = importer.load_export(csv_path)
    console.print(f"Loaded [bold]{len(entries)}[/bold] entries.\n")

    if use_hibp:
        console.print("[bold cyan]Checking against Have I Been Pwned[/bold cyan] "
                       "(k-anonymity — no plaintext or full hash ever sent)...")

        def progress_cb(done, total):
            pass  # rich track() below handles the visual; kept for future use

        for entry in track(entries, description="Checking breaches..."):
            if not hasattr(entry, "breach_count"):
                entry.breach_count = hibp.check_password_breached(entry.password)
    else:
        for entry in entries:
            entry.breach_count = -1
        console.print("[yellow]Skipping HIBP check (offline mode).[/yellow]")

    console.print("\n[bold cyan]Running deep pattern analysis[/bold cyan]...")
    for entry in entries:
        entry.flags = pattern_detect.analyze_entry(entry)

    clusters = pattern_detect.find_similar_clusters(entries)
    clustered_indices = {idx for cluster in clusters for idx in cluster}
    for entry in entries:
        in_cluster = entry.row_index in clustered_indices
        if in_cluster:
            entry.flags.append("similar to another saved password")
        entry.risk_score = entropy.compute_risk_score(
            entry, entry.flags, entry.breach_count, in_cluster
        )
        entry.risk_level = entropy.risk_level_for_score(entry.risk_score)

    console.print()
    report.print_summary(entries)
    report.print_detail_table(entries)

    if clusters:
        console.print(f"\n[yellow]Found {len(clusters)} cluster(s) of similar passwords "
                       f"across different accounts — see 'similar to another saved "
                       f"password' flags above.[/yellow]")

    return entries


def run_fix(csv_path: str, output_path: str, length: int, min_risk: str, use_hibp: bool = True):
    entries = run_audit(csv_path, use_hibp=use_hibp)

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "GOOD": 3}
    threshold = risk_order[min_risk]
    flagged = [e for e in entries if risk_order[e.risk_level] <= threshold]

    if not flagged:
        console.print(f"\n[green]No entries at or above '{min_risk}' risk. Nothing to fix.[/green]")
        return

    console.print(f"\n[bold cyan]Generating replacements[/bold cyan] for "
                   f"{len(flagged)} flagged entries...")
    pairs = [(e, generator.generate_replacement_for(e, length)) for e in flagged]

    report.print_replacement_preview(pairs)
    exporter.export_replacements(pairs, output_path)
    console.print(f"\n[bold green]Wrote {len(pairs)} replacement(s) to {output_path}[/bold green]")
    console.print("[dim]Next: manually update each site with its new password, "
                   "then delete the old saved entry.[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="LeakHawk — local-first password audit and remediation."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser("audit", help="Audit a password export CSV.")
    audit_parser.add_argument("csv_path", help="Path to browser password export CSV.")
    audit_parser.add_argument("--no-hibp", action="store_true",
                               help="Skip the HIBP breach check (fully offline).")

    fix_parser = subparsers.add_parser("fix", help="Audit and generate replacement passwords.")
    fix_parser.add_argument("csv_path", help="Path to browser password export CSV.")
    fix_parser.add_argument("--output", default="leakhawk_replacements.csv",
                             help="Output CSV path for new passwords.")
    fix_parser.add_argument("--length", type=int, default=14,
                             help="Length for generated passwords (10-16).")
    fix_parser.add_argument("--min-risk", default="MEDIUM",
                             choices=["CRITICAL", "HIGH", "MEDIUM", "GOOD"],
                             help="Minimum risk level to generate a replacement for.")
    fix_parser.add_argument("--no-hibp", action="store_true",
                             help="Skip the HIBP breach check (fully offline).")

    args = parser.parse_args()

    print_banner()

    try:
        if args.command == "audit":
            run_audit(args.csv_path, use_hibp=not args.no_hibp)
        elif args.command == "fix":
            run_fix(args.csv_path, args.output, args.length, args.min_risk,
                     use_hibp=not args.no_hibp)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
