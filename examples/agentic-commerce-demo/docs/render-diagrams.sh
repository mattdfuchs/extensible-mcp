#!/usr/bin/env bash
# Re-render the Mermaid diagrams in architecture.md to docs/img/*.svg.
# The doc embeds these SVGs (so they show in any previewer) and keeps the
# Mermaid source in <details> blocks; run this after editing that source.
#
#   docs/render-diagrams.sh        # needs npx (mermaid-cli fetched on demand)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
doc="$here/architecture.md"
mkdir -p "$here/img"

# The order of ```mermaid blocks in architecture.md maps to these names.
names=(components commerce-seq convergence)

python3 - "$doc" "$here/img" "${names[@]}" <<'PY'
import re, sys, pathlib
doc, outdir, *names = sys.argv[1:]
blocks = re.findall(r"```mermaid\n(.*?)```", pathlib.Path(doc).read_text(), re.S)
if len(blocks) != len(names):
    sys.exit(f"expected {len(names)} mermaid blocks, found {len(blocks)}")
for name, body in zip(names, blocks):
    pathlib.Path(f"{outdir}/{name}.mmd").write_text(body)
print(" ".join(names))
PY

for n in "${names[@]}"; do
  npx -y -p @mermaid-js/mermaid-cli mmdc -i "$here/img/$n.mmd" -o "$here/img/$n.svg" -b white
  rm -f "$here/img/$n.mmd"
  echo "rendered img/$n.svg"
done
