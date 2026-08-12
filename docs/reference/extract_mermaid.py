"""Extract Mermaid diagrams from saved Trace37 HTML snapshots."""
import json
import os
import re

BASE = os.path.dirname(os.path.abspath(__file__))


def extract_blocks(html: str) -> list[str]:
    blocks: list[str] = []
    for m in re.finditer(r'<div class="mermaid">(.*?)</div>', html, re.DOTALL | re.I):
        blocks.append(m.group(1).strip())
    for m in re.finditer(r"```(?:mermaid)?\s*(%%\{[\s\S]*?)```", html, re.I):
        if "flowchart" in m.group(1) or "sequenceDiagram" in m.group(1):
            blocks.append(m.group(1).strip())
    # Hugo/minified blog: diagrams in <pre><code> or bare after %%{init
    for m in re.finditer(
        r"(%%\{init:[\s\S]*?\}%%\s*flowchart (?:TB|TD|LR|BT)[\s\S]*?)(?=</code>|</pre>|%%\{init:|</div>|<script|<a href=)",
        html,
        re.I,
    ):
        blocks.append(m.group(1).strip())
    for m in re.finditer(
        r"(flowchart (?:TB|TD|LR|BT)[\s\S]*?)(?=</code>|</pre>|flowchart (?:TB|TD|LR|BT)|%%\{init:|</div>|<script)",
        html,
        re.I,
    ):
        chunk = m.group(1).strip()
        if len(chunk) > 80 and chunk not in blocks:
            blocks.append(chunk)
    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for b in blocks:
        key = b[:200]
        if key not in seen:
            seen.add(key)
            unique.append(b)
    return unique


def main() -> None:
    inventory = []
    for fn in sorted(os.listdir(BASE)):
        if not fn.endswith(".html"):
            continue
        path = os.path.join(BASE, fn)
        text = open(path, encoding="utf-8", errors="replace").read()
        blocks = extract_blocks(text)
        for i, block in enumerate(blocks):
            labels = re.findall(r'\["([^"\\]+(?:<br[^>]*)?[^"\\]*)"\]', block)
            stem = fn.replace(".html", f"-mermaid-{i}.mmd")
            open(os.path.join(BASE, stem), "w", encoding="utf-8").write(block + "\n")
            inventory.append(
                {
                    "file": fn,
                    "artifact": stem,
                    "index": i,
                    "has_flowchart": "flowchart" in block,
                    "has_sequence": "sequenceDiagram" in block,
                    "label_count": len(labels),
                    "labels": labels,
                }
            )
        print(f"{fn}: {len(blocks)} diagram(s)")

    open(os.path.join(BASE, "mermaid-inventory.json"), "w", encoding="utf-8").write(
        json.dumps(inventory, indent=2)
    )
    print(f"Wrote {len(inventory)} diagrams to inventory")


if __name__ == "__main__":
    main()
