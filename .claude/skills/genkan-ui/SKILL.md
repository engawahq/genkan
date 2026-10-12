---
name: genkan-ui
description: Change Genkan's sign-in pages — askama templates, TypeScript, Tailwind CSS, translations — while keeping the strict CSP, committed reproducible assets, size budgets and WCAG 2.2 AA contrast. Use for any change under ui/ or crates/genkan-ui.
---

# Sign-in pages

- **Where things are.** Sources: `ui/src/*.ts` (scripts), `ui/styles/*.css` (Tailwind v4 input).
  Templates: `crates/genkan-ui/templates/` (askama; shadcn/ui class strings). Built output:
  `crates/genkan-ui/assets/` (committed, embedded with `include_bytes!`). Page routes live in
  `crates/genkan-signin/src/pages.rs`; rendering in `crates/genkan-ui/src/pages.rs`.
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
- **Text.** Every string is a field of `Messages` in `crates/genkan-ui/src/i18n.rs` with English,
  Traditional Chinese (Taiwan usage, 通行密鑰) and Simplified Chinese (通行密钥) values; scripts get
  their messages from `data-msg-*` attributes. A missing translation is a compile error.
- **Contrast.** `contrast.py` in this skill reads the tokens from `ui/styles/app.css` and checks
  every colour pair the pages render (text ≥ 4.5:1, boundaries and focus rings ≥ 3:1), with
  alpha compositing; it exits 1 on any failure. Run it after changing a token or a colour class:
  `python3 .claude/skills/genkan-ui/contrast.py` (inside `nix develop`). Try a value first with
  `--set light:border='oklch(0.6 0 0)'`. When a template starts rendering a new pair (a variant,
  state or surface), add it to the inventory in the script. Update the `A11Y` comments in
  `ui/styles/app.css` with the new ratios.
- **Budgets.** Brotli sizes are checked by `scripts/ui-budget.sh`; raise a budget only with a
  reason in the commit.
