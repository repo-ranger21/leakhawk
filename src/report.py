"""
report.py — Terminal report rendering using `rich`.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange3",
    "MEDIUM": "bold yellow",
    "GOOD": "bold green",
}


def print_summary(entries) -> None:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "GOOD": 0}
    for e in entries:
        counts[e.risk_level] += 1

    summary = "  ".join(
        f"[{RISK_COLORS[level]}]{level}: {counts[level]}[/{RISK_COLORS[level]}]"
        for level in ["CRITICAL", "HIGH", "MEDIUM", "GOOD"]
    )
    console.print(Panel(summary, title="LeakHawk Audit Summary", expand=False))


def print_detail_table(entries) -> None:
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Site")
    table.add_column("Username")
    table.add_column("Risk")
    table.add_column("Breached")
    table.add_column("Flags")

    # Sort worst-first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "GOOD": 3}
    sorted_entries = sorted(entries, key=lambda e: order[e.risk_level])

    for e in sorted_entries:
        breach_display = (
            f"{e.breach_count:,}x" if getattr(e, "breach_count", 0) > 0
            else ("unknown" if getattr(e, "breach_count", 0) == -1 else "no")
        )
        color = RISK_COLORS[e.risk_level]
        table.add_row(
            e.site_name,
            e.username,
            f"[{color}]{e.risk_level}[/{color}]",
            breach_display,
            ", ".join(e.flags) if e.flags else "—",
        )

    console.print(table)


def print_replacement_preview(pairs) -> None:
    """pairs: list of (entry, new_password) tuples."""
    table = Table(show_header=True, header_style="bold cyan", title="Generated Replacements")
    table.add_column("Site")
    table.add_column("Username")
    table.add_column("New Password")

    for entry, new_pw in pairs:
        table.add_row(entry.site_name, entry.username, new_pw)

    console.print(table)
    console.print(
        "[dim]Copy these into your password manager, then update each site "
        "before deleting the old entries.[/dim]"
    )
