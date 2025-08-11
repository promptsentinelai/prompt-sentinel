#!/usr/bin/env python3
# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Script to update copyright headers in Python files."""

import sys
from pathlib import Path

# The copyright header to add
COPYRIGHT_HEADER = """# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""


def update_file(filepath):
    """Update a single Python file with the copyright header."""
    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    # Check if file already has a copyright header
    if content.startswith("# Copyright"):
        # Remove old copyright header (up to first non-comment line or docstring)
        lines = content.split("\n")
        i = 0
        while i < len(lines) and (lines[i].startswith("#") or lines[i].strip() == ""):
            i += 1
        content = "\n".join(lines[i:])

    # Add new header
    new_content = COPYRIGHT_HEADER + content

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(new_content)

    return True


def main():
    """Update all Python files in the src directory."""
    src_dir = Path(__file__).parent.parent / "src"

    if not src_dir.exists():
        print(f"Error: src directory not found at {src_dir}")
        sys.exit(1)

    python_files = list(src_dir.glob("**/*.py"))

    print(f"Found {len(python_files)} Python files to update")

    updated = 0
    for filepath in python_files:
        try:
            if update_file(filepath):
                updated += 1
                print(f"✓ Updated {filepath.relative_to(src_dir.parent)}")
        except Exception as e:
            print(f"✗ Error updating {filepath}: {e}")

    print(f"\nSuccessfully updated {updated}/{len(python_files)} files")


if __name__ == "__main__":
    main()
