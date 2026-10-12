# genkan-ui

Genkan's sign-in pages: server-rendered HTML, embedded static assets, translations and the
security headers every page carries. Routing and the data behind each page belong to the
caller.

## Modules

- `pages`: renders the sign-in, enrolment, error and notice pages from askama templates in
  `templates/`. askama compiles templates at build time and escapes HTML by default, so the
  client name, `login_hint` and error details cannot inject markup.
- `assets`: serves the embedded CSS, scripts and font at `/assets/{name}` by exact name, cached
  as immutable and versioned by the first 16 hex digits of their SHA-256.
- `i18n`: English, Traditional Chinese (Taiwan) and Simplified Chinese. The language is the
  `?lang=` switcher, then the client's `ui_locales` where the caller has it, then
  `Accept-Language` by quality ([RFC 9110 §12.5.4][rfc9110]), then English.
- `harden` and `CSP`: the response headers below.

Depends only on `genkan-core`. Used by `genkan-oauth` (the error page), `genkan-signin` (the
page routes) and the `genkan` server.

## Frontend source and build

The sources live in `ui/` at the repository root: `ui/styles/app.css` (theme tokens and local
accessibility overrides marked `A11Y`), `ui/styles/shadcn.css` (vendored shadcn/ui base styles)
and the TypeScript in `ui/src/`. `scripts/build-ui.sh` runs Tailwind CSS v4 over `app.css`,
which scans the templates for class names, and `bun build --minify` over `login.ts` and
`setup.ts`. The output in `assets/` is committed and embedded with `include_bytes!`, so
`cargo build` needs no Node, bun or Tailwind and nothing is loaded from another origin. CI
rebuilds the assets and fails if they differ from the committed files, typechecks the scripts,
and runs `scripts/ui-budget.sh`, which limits the brotli-compressed size to 8 KiB for `app.css`
and 3 KiB for each script. There is no `package.json` and no npm dependency.

The scripts POST JSON and navigate with `location.assign`; no page submits a form, so the CSP
can say `form-action 'none'`. They convert WebAuthn JSON by hand rather than with
`PublicKeyCredential.parse*FromJSON`, which older Safari versions lack. They write only
`textContent`, never HTML, take their messages from `data-msg-*` attributes in the page language,
store nothing in the browser and never see a token.

## Security headers

Every HTML page sets a CSP with `default-src 'none'`, `'self'` sources only, no inline script or
style ([CSP Level 3][csp]), `frame-ancestors 'none'` and Trusted Types with no policy
([Trusted Types][tt]), so any string-to-HTML sink throws. With `X-Frame-Options: DENY` this
meets the clickjacking defence of [RFC 9700 §4.16][rfc9700]. Pages also send `nosniff`,
`Referrer-Policy: no-referrer`, `Cache-Control: no-store`, same-origin COOP and CORP, and a
`Permissions-Policy` allowing only WebAuthn. The error page for an untrusted authorization
request is shown with status 400 and no redirect ([RFC 6749 §4.1.2.1][rfc6749]).

## Accessibility

The pages target [WCAG 2.2][wcag] AA, follow the operating system's dark mode without script,
honour reduced motion, and keep a focus outline in forced-colours mode. Contrast ratios were
computed from the OKLCH tokens (`OKLab` to gamut-clipped sRGB, alpha composited in sRGB as browsers
do, WCAG relative luminance); where the upstream theme fails, `app.css` overrides it:

| Pair | Light | Dark | Needed |
|---|---|---|---|
| Foreground on card | 19.79 | 17.16 | 4.5 |
| Muted foreground on card / on muted | 6.00 / 5.50 (upstream 4.34 on muted) | 6.91 / 5.83 | 4.5 |
| Destructive text on card | 4.76 | 6.19 | 4.5 |
| Primary button text | 17.16 | 14.22 | 4.5 |
| Language links (foreground at 70 %) | 7.33 | 7.82 | 4.5 |
| Input border on card | 3.95 (upstream 1.26) | 4.50 (upstream 1.57) | 3 |
| Focus ring on card | 4.73 (upstream 2.59) | 6.91 (upstream 1.87) | 3 |

The destructive button variant (destructive text on its own 10 % tint: 3.99:1 light, 5.46:1
dark) does not meet 4.5:1 in light mode; no page uses it.

## Credits

Markup and class strings are copied from [shadcn/ui][shadcn] (style `base-nova`, MIT License);
`ui/styles/shadcn.css` is its base stylesheet. Icons are inline Phosphor SVGs (MIT
License). The [Geist][geist] font is embedded under the SIL Open Font License 1.1
(`assets/LICENSE-Geist.txt`); Chinese text uses the system's CJK fonts.

## References

- R. Fielding, M. Nottingham, and J. Reschke, Eds., "HTTP Semantics," RFC 9110, IETF,
  Jun. 2022. <https://www.rfc-editor.org/rfc/rfc9110>
- D. Hardt, Ed., "The OAuth 2.0 Authorization Framework," RFC 6749, IETF, Oct. 2012.
  <https://www.rfc-editor.org/rfc/rfc6749>
- T. Lodderstedt, J. Bradley, A. Labunets, and D. Fett, "Best Current Practice for OAuth 2.0
  Security," RFC 9700, IETF, Jan. 2025. <https://www.rfc-editor.org/rfc/rfc9700>
- W3C, "Content Security Policy Level 3," W3C Working Draft. <https://www.w3.org/TR/CSP3/>
- W3C, "Trusted Types," W3C Working Draft. <https://www.w3.org/TR/trusted-types/>
- W3C, "Web Content Accessibility Guidelines (WCAG) 2.2," W3C Recommendation, Oct. 2023.
  <https://www.w3.org/TR/WCAG22/>

[rfc9110]: https://www.rfc-editor.org/rfc/rfc9110
[rfc6749]: https://www.rfc-editor.org/rfc/rfc6749
[rfc9700]: https://www.rfc-editor.org/rfc/rfc9700
[csp]: https://www.w3.org/TR/CSP3/
[tt]: https://www.w3.org/TR/trusted-types/
[wcag]: https://www.w3.org/TR/WCAG22/
[shadcn]: https://ui.shadcn.com
[geist]: https://github.com/vercel/geist-font
