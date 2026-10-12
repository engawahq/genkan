---
name: genkan-ui
description: Change Genkan's sign-in pages — askama templates, TypeScript, Tailwind CSS, translations — while keeping the strict CSP, committed reproducible assets, size budgets and WCAG 2.2 AA contrast. Use for any change under ui/ or crates/genkan-ui.
---

# Sign-in pages

- **Where things are.** Sources: `ui/src/*.ts` (scripts), `ui/styles/*.css` (Tailwind v4 input).
  Templates: `crates/genkan-ui/templates/` (askama; shadcn/ui class strings). Built output:
  `crates/genkan-ui/assets/` (committed, embedded with `include_bytes!`). Page routes live in
  `genkan-signin/src/pages.rs`; rendering in `genkan-ui/src/pages.rs`.
- **Build and check** (inside `nix develop`):
  ```sh
  ./scripts/build-ui.sh && git diff --stat -- crates/genkan-ui/assets
  tsc -p ui && ./scripts/ui-budget.sh
  cargo nextest run -p genkan-signin -E 'binary(pages)'
  ```
  Commit the rebuilt assets with the source change; CI rebuilds and fails on any difference.
- **CSP rules.** No inline `<script>`, `<style>`, `style=""` or `on*=` handlers; no URLs to other
  origins; scripts write only `textContent`, `hidden` and `location` (Trusted Types `'none'`). The
  page tests enforce this.
- **Text.** Every string is a field of `Messages` in `genkan-ui/src/i18n.rs` with English,
  Traditional Chinese (Taiwan usage, 通行密鑰) and Simplified Chinese (通行密钥) values; scripts get
  their messages from `data-msg-*` attributes. A missing translation is a compile error.
- **Contrast.** Changing a colour token means recomputing WCAG contrast for every pair the pages
  use (text ≥ 4.5:1, borders and focus rings ≥ 3:1), including alpha compositing.
  `contrast.py` in this skill does the OKLCH → sRGB → WCAG computation:
  `python3 .claude/skills/genkan-ui/contrast.py`. Update the table in the `genkan-ui` docs and the
  `A11Y` comments in `ui/styles/app.css`.
- **Budgets.** Brotli sizes are checked by `scripts/ui-budget.sh`; raise a budget only with a
  reason in the commit.
