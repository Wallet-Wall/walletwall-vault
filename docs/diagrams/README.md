# Adaptive Mermaid diagrams

WalletWall vault documentation publishes transparent light and dark SVG variants
selected with `prefers-color-scheme`. The canonical sources for the remaining vault
diagrams live in `docs/diagrams/adaptive/`, with their page and asset mappings in
`docs/diagrams/adaptive-manifest.json`.

The earlier hybrid-architecture pilot retains its paired light/dark `.mmd` sources at
the top of this directory. All variants preserve the complete documented graph.

When a diagram changes, update its Mermaid source, render both WalletWall variants
with Mermaid 11, and validate the standalone SVG files in a real browser at desktop
and narrow/mobile widths. SVG roots must remain transparent and script-free.
