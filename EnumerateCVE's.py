import datetime
import subprocess
import re
from collections import defaultdict

OUTPUT_FILE = f"cve_report_{datetime.datetime.now().strftime('%Y-%m-%d')}.md"


def run_command():
    """Run dnf command and return output."""
    try:
        result = subprocess.run(
            ["dnf", "updateinfo", "list", "cves"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout

    except subprocess.CalledProcessError as e:
        print("Error running dnf command:")
        print(e.stderr)
        exit(1)

    except FileNotFoundError:
        print("dnf command not found.")
        exit(1)


def parse_cves(output):
    """
    Parse dnf output.

    Expected format examples:
    FEDORA-2026-xxxx  Moderate/Sec. package-name CVE-2026-1234
    """

    packages = defaultdict(lambda: {
        "cves": set(),
        "iavas": set(),
        "description": "  "
    })

    for line in output.splitlines():

        # Skip headers/empty lines
        if not line.strip():
            continue

        # Find CVEs
        cve_matches = re.findall(
            r"CVE-\d{4}-\d+",
            line,
            re.IGNORECASE
        )

        if not cve_matches:
            continue

        # Attempt to identify package
        parts = line.split()

        package = None

        for part in parts:
            if (
                not part.startswith("CVE-")
                and not part.startswith("RHBA-")
                and not part.startswith("RHEL-")
                and "-" in part
            ):
                package = part
                break

        if not package:
            package = "Unknown"

        packages[package]["cves"].update(cve_matches)

        # Detect IAVA IDs if present
        iava_matches = re.findall(
            r"IAVA-\d+",
            line,
            re.IGNORECASE
        )

        packages[package]["iavas"].update(iava_matches)

    return packages


def natural_sort_key(value):
    """
    Sort strings naturally:
    pkg2 before pkg10
    """
    return [
        int(x) if x.isdigit() else x.lower()
        for x in re.split(r"(\d+)", value)
    ]


def write_markdown(data):
    """
    Write the parsed CVE data to a Markdown file.

    This function creates a simple table with one row per package.
    It writes package names, CVE IDs, IAVA IDs, and any description text.
    """

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write(
            "# CVE Update Report\n\n"
        )

        f.write(
            "| Package | CVE(s) | IAVA(s) | Description |\n"
        )
        f.write(
            "|---|---|---|---|\n"
        )

        for package in sorted(
            data.keys(),
            key=natural_sort_key
        ):

            cves = ", ".join(
                sorted(data[package]["cves"])
            )

            iavas = ", ".join(
                sorted(data[package]["iavas"])
            )

            description = data[package]["description"]

            f.write(
                f"| {package} | {cves} | {iavas} | {description} |\n"
            )


def main():
    """
    Orchestrate the data collection and report generation.

    This function runs the dnf command, parses its output, and writes
    the resulting Markdown report to disk.
    """

    print("Running dnf updateinfo...")
    
    output = run_command()

    if not output.strip():
        print("No CVE entries found.")
        return

    parsed = parse_cves(output)

    write_markdown(parsed)

    print(
        f"Markdown report created: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
