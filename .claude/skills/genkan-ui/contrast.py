#!/usr/bin/env python3
"""WCAG 2.2 contrast of every colour pair the sign-in pages render.

Reads the colour tokens from ``ui/styles/app.css`` (the light ``:root`` block and
its ``prefers-color-scheme: dark`` override), so the numbers follow the
stylesheet instead of a copy. Each pair names the template that renders it.

Colour pipeline:

1. OKLCH to linear sRGB with the OKLab matrices of B. Ottosson, "A perceptual
   color space for image processing", 2020,
   https://bottosson.github.io/posts/oklab/, then clipped to the sRGB gamut.
2. Alpha (a token's own alpha times a Tailwind ``/NN`` modifier) is composited
   in gamma-encoded sRGB, as browsers do.
3. Contrast ratio from relative luminance,
   https://www.w3.org/TR/WCAG22/#dfn-contrast-ratio.

Requirements: text 4.5:1 (1.4.3); component boundaries and focus indicators 3:1
(1.4.11, 2.4.13). Not checked, because WCAG does not require them: disabled
controls, the decorative separator line beside "or", and the card outline
(``ring-foreground/10``), which is not a control. Not checked, because no page
renders them: the ``aria-invalid`` styles (no page passes ``error`` to
``ui::field``), the card footer, and button variants other than default and
outline. Add a pair when a page starts rendering one.

Usage, from the repository root inside ``nix develop``::

    python3 .claude/skills/genkan-ui/contrast.py
    python3 .claude/skills/genkan-ui/contrast.py --set light:border='oklch(0.6 0 0)'

Exit status: 0 when every pair passes, 1 when any fails, 2 on bad input.
"""

from __future__ import annotations

import argparse
import enum
import math
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

type Rgb = tuple[float, float, float]
"""Linear-light sRGB, each channel in ``[0, 1]``."""

type Tokens = dict[str, Oklch]
"""Colour custom properties of one theme, keyed without the leading ``--``."""

type Layers = tuple[Paint, ...]
"""Paints from the bottom up; the first is opaque."""

DEFAULT_CSS = Path("ui/styles/app.css")
THEMES = ("light", "dark")

_OKLCH = re.compile(r"oklch\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*(?:/\s*([\d.]+)(%?))?\s*\)")
_ROOT_BLOCK = re.compile(r"(?P<dark>@media\s*\(prefers-color-scheme:\s*dark\)\s*\{\s*)?:root\s*\{(?P<body>[^}]*)\}")
_DECLARATION = re.compile(r"--(?P<name>[\w-]+)\s*:\s*(?P<value>oklch\([^)]*\))")


# Colour science


@dataclass(frozen=True, slots=True)
class Oklch:
    """A CSS ``oklch()`` colour; ``alpha`` is in ``[0, 1]``."""

    lightness: float
    chroma: float
    hue: float
    alpha: float = 1.0

    @classmethod
    def parse(cls, text: str) -> Oklch:
        """Parse ``oklch(L C H)`` or ``oklch(L C H / A)``, ``A`` a number or percentage.

        >>> Oklch.parse("oklch(1 0 0 / 45%)")
        Oklch(lightness=1.0, chroma=0.0, hue=0.0, alpha=0.45)
        """
        match = _OKLCH.fullmatch(text.strip())
        if match is None:
            raise ValueError(f"not an oklch() colour: {text!r}")
        lightness, chroma, hue, alpha, percent = match.groups()
        a = 1.0 if alpha is None else float(alpha) / (100 if percent else 1)
        return cls(float(lightness), float(chroma), float(hue), a)

    def to_linear_srgb(self) -> Rgb:
        """Convert to linear sRGB, clipped to the gamut; alpha is ignored.

        >>> Oklch(1, 0, 0).to_linear_srgb() == (1.0, 1.0, 1.0)
        True
        """
        a = self.chroma * math.cos(math.radians(self.hue))
        b = self.chroma * math.sin(math.radians(self.hue))
        long = (self.lightness + 0.3963377774 * a + 0.2158037573 * b) ** 3
        medium = (self.lightness - 0.1055613458 * a - 0.0638541728 * b) ** 3
        short = (self.lightness - 0.0894841775 * a - 1.2914855480 * b) ** 3
        return _clip(
            (
                4.0767416621 * long - 3.3077115913 * medium + 0.2309699292 * short,
                -1.2684380046 * long + 2.6097574011 * medium - 0.3413193965 * short,
                -0.0041960863 * long - 0.7034186147 * medium + 1.7076147010 * short,
            )
        )


def _clip(rgb: Iterable[float]) -> Rgb:
    r, g, b = (min(1.0, max(0.0, c)) for c in rgb)
    return (r, g, b)


def _encode(c: float) -> float:
    return 12.92 * c if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055


def _decode(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def composite(top: Rgb, bottom: Rgb, alpha: float) -> Rgb:
    """Draw ``top`` at ``alpha`` over opaque ``bottom``, blending in gamma-encoded sRGB."""
    return _clip(_decode(alpha * _encode(t) + (1 - alpha) * _encode(b)) for t, b in zip(top, bottom, strict=True))


def luminance(rgb: Rgb) -> float:
    """WCAG relative luminance of a linear sRGB colour."""
    r, g, b = rgb
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: Rgb, b: Rgb) -> float:
    """WCAG contrast ratio, from 1 to 21.

    >>> round(contrast((1.0, 1.0, 1.0), (0.0, 0.0, 0.0)), 2)
    21.0
    """
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


# Paints and pairs


@dataclass(frozen=True, slots=True)
class Paint:
    """A token drawn at a Tailwind opacity modifier: ``bg-input/30`` is ``Paint("input", 0.3)``."""

    token: str
    opacity: float = 1.0

    def __str__(self) -> str:
        return self.token if self.opacity == 1 else f"{self.token}/{round(self.opacity * 100)}"

    def over(self, below: Rgb, tokens: Tokens) -> Rgb:
        """Draw this paint, including its token's own alpha, over an opaque colour."""
        colour = tokens[self.token]
        return composite(colour.to_linear_srgb(), below, colour.alpha * self.opacity)


def flatten(layers: Layers, tokens: Tokens) -> Rgb:
    """Composite ``layers`` into the opaque colour a viewer sees."""
    base, *rest = layers
    colour = tokens[base.token]
    if colour.alpha * base.opacity != 1:
        raise ValueError(f"bottom layer {base} is not opaque")
    rgb = colour.to_linear_srgb()
    for paint in rest:
        rgb = paint.over(rgb, tokens)
    return rgb


class Kind(enum.Enum):
    """What a pair is, and the WCAG success criterion and minimum ratio that apply."""

    TEXT = ("1.4.3", 4.5)
    BOUNDARY = ("1.4.11", 3.0)
    FOCUS = ("2.4.13", 3.0)

    def __init__(self, criterion: str, minimum: float) -> None:
        self.criterion = criterion
        self.minimum = minimum


@dataclass(frozen=True, slots=True, kw_only=True)
class Pair:
    """A foreground paint against the colour beside it, as a template renders it.

    ``fg`` is drawn over ``drawn_on``, which defaults to ``bg``. They differ for
    borders: with ``bg-clip-padding`` a border sits on the card, not on the
    control's own fill, yet must still contrast with that fill.
    """

    name: str
    kind: Kind
    fg: Paint
    bg: Layers
    source: str
    drawn_on: Layers | None = None

    def ratio(self, tokens: Tokens) -> float:
        fg = self.fg.over(flatten(self.drawn_on or self.bg, tokens), tokens)
        return contrast(fg, flatten(self.bg, tokens))


def paint(token: str, opacity: float = 1.0) -> Paint:
    return Paint(token, opacity)


def stack(*paints: Paint) -> Layers:
    return paints


# Inventory. Keep in step with crates/genkan-ui/templates and ui/styles/app.css.

PAGE = stack(paint("muted"))  # base.html <body class="bg-muted">
CARD = stack(paint("card"))  # ui.html card: bg-card
LIGHT_OUTLINE_FILL = stack(paint("card"), paint("background"))  # outline button: bg-background
DARK_FIELD = stack(paint("card"), paint("input", 0.3))  # input and outline button: dark:bg-input/30

COMMON: tuple[Pair, ...] = (
    Pair(
        name="card text",
        kind=Kind.TEXT,
        fg=paint("card-foreground"),
        bg=CARD,
        source="ui.html card, field label, alert title",
    ),
    Pair(
        name="muted text on card",
        kind=Kind.TEXT,
        fg=paint("muted-foreground"),
        bg=CARD,
        source="card and field descriptions, #status, separator text, alert description",
    ),
    Pair(
        name="error text on card",
        kind=Kind.TEXT,
        fg=paint("destructive"),
        bg=CARD,
        source="login/setup #error, error.html destructive alert",
    ),
    Pair(
        name="primary button text",
        kind=Kind.TEXT,
        fg=paint("primary-foreground"),
        bg=stack(paint("card"), paint("primary")),
        source="button_cls default",
    ),
    Pair(
        name="primary button text, hover",
        kind=Kind.TEXT,
        fg=paint("primary-foreground"),
        bg=stack(paint("card"), paint("primary", 0.8)),
        source="button_cls default hover:bg-primary/80",
    ),
    Pair(
        name="language link",
        kind=Kind.TEXT,
        fg=paint("foreground", 0.7),
        bg=PAGE,
        source="base.html nav text-foreground/70",
    ),
    Pair(
        name="language link, current",
        kind=Kind.TEXT,
        fg=paint("foreground"),
        bg=PAGE,
        source="base.html aria-[current]:text-foreground",
    ),
    Pair(
        name="primary button against card",
        kind=Kind.BOUNDARY,
        fg=paint("primary"),
        bg=CARD,
        source="button_cls default bg-primary",
    ),
    Pair(
        name="input border against card",
        kind=Kind.BOUNDARY,
        fg=paint("input"),
        bg=CARD,
        source="input_cls border-input",
    ),
    Pair(
        name="focus ring against card",
        kind=Kind.FOCUS,
        fg=paint("ring"),
        bg=CARD,
        source="button_cls, input_cls focus-visible:ring-ring",
    ),
    Pair(
        name="focus ring against page",
        kind=Kind.FOCUS,
        fg=paint("ring"),
        bg=PAGE,
        source="base.html language link focus-visible:ring-ring",
    ),
)

LIGHT: tuple[Pair, ...] = (
    Pair(
        name="input placeholder",
        kind=Kind.TEXT,
        fg=paint("muted-foreground"),
        bg=CARD,
        source="input_cls placeholder:text-muted-foreground",
    ),
    Pair(
        name="outline button text",
        kind=Kind.TEXT,
        fg=paint("card-foreground"),
        bg=LIGHT_OUTLINE_FILL,
        source="button_cls outline bg-background",
    ),
    Pair(
        name="outline button text, hover",
        kind=Kind.TEXT,
        fg=paint("foreground"),
        bg=stack(paint("card"), paint("muted")),
        source="button_cls outline hover:bg-muted",
    ),
    Pair(
        name="outline button border against card",
        kind=Kind.BOUNDARY,
        fg=paint("border"),
        bg=CARD,
        source="upstream.html, button_cls outline border-border",
    ),
    Pair(
        name="outline button border against fill",
        kind=Kind.BOUNDARY,
        fg=paint("border"),
        bg=LIGHT_OUTLINE_FILL,
        drawn_on=CARD,
        source="upstream.html, button_cls outline border-border bg-background",
    ),
)

DARK: tuple[Pair, ...] = (
    Pair(
        name="input text",
        kind=Kind.TEXT,
        fg=paint("card-foreground"),
        bg=DARK_FIELD,
        source="input_cls dark:bg-input/30",
    ),
    Pair(
        name="input placeholder",
        kind=Kind.TEXT,
        fg=paint("muted-foreground"),
        bg=DARK_FIELD,
        source="input_cls placeholder:text-muted-foreground dark:bg-input/30",
    ),
    Pair(
        name="input border against fill",
        kind=Kind.BOUNDARY,
        fg=paint("input"),
        bg=DARK_FIELD,
        drawn_on=CARD,
        source="input_cls border-input dark:bg-input/30",
    ),
    Pair(
        name="outline button text",
        kind=Kind.TEXT,
        fg=paint("card-foreground"),
        bg=DARK_FIELD,
        source="button_cls outline dark:bg-input/30",
    ),
    Pair(
        name="outline button text, hover",
        kind=Kind.TEXT,
        fg=paint("foreground"),
        bg=stack(paint("card"), paint("input", 0.5)),
        source="button_cls outline dark:hover:bg-input/50",
    ),
    Pair(
        name="outline button border against card",
        kind=Kind.BOUNDARY,
        fg=paint("input"),
        bg=CARD,
        source="upstream.html, button_cls outline dark:border-input",
    ),
    Pair(
        name="outline button border against fill",
        kind=Kind.BOUNDARY,
        fg=paint("input"),
        bg=DARK_FIELD,
        drawn_on=CARD,
        source="upstream.html, button_cls outline dark:border-input dark:bg-input/30",
    ),
)

PAIRS: dict[str, tuple[Pair, ...]] = {"light": COMMON + LIGHT, "dark": COMMON + DARK}


# Input and output


def read_tokens(css: str) -> dict[str, Tokens]:
    """Colour tokens of the light ``:root`` block and its dark-scheme override.

    >>> css = ":root { --a: oklch(1 0 0); --b: oklch(0.5 0 0); }"
    >>> css += " @media (prefers-color-scheme: dark) { :root { --a: oklch(0 0 0); } }"
    >>> themes = read_tokens(css)
    >>> themes["dark"]["a"].lightness, themes["dark"]["b"].lightness
    (0.0, 0.5)
    """
    themes: dict[str, Tokens] = {theme: {} for theme in THEMES}
    for block in _ROOT_BLOCK.finditer(css):
        theme = "dark" if block["dark"] else "light"
        for declaration in _DECLARATION.finditer(block["body"]):
            themes[theme][declaration["name"]] = Oklch.parse(declaration["value"])
    if not themes["light"]:
        raise ValueError("no oklch() tokens in a light :root block")
    themes["dark"] = themes["light"] | themes["dark"]
    return themes


def apply_overrides(themes: dict[str, Tokens], overrides: Iterable[str]) -> None:
    """Apply ``THEME:TOKEN=oklch(...)`` overrides in place, to try a value before editing the CSS."""
    for override in overrides:
        target, _, value = override.partition("=")
        theme, _, token = target.partition(":")
        token = token.removeprefix("--")
        if token not in themes.get(theme, {}):
            raise ValueError(f"--set {override!r}: expected light:TOKEN or dark:TOKEN with an existing token")
        themes[theme][token] = Oklch.parse(value)


@dataclass(frozen=True, slots=True)
class Result:
    theme: str
    pair: Pair
    ratio: float

    @property
    def passed(self) -> bool:
        return self.ratio >= self.pair.kind.minimum


def evaluate(themes: dict[str, Tokens]) -> list[Result]:
    return [Result(theme, pair, pair.ratio(themes[theme])) for theme in THEMES for pair in PAIRS[theme]]


def report(results: Sequence[Result]) -> str:
    """Format results as an aligned table; the last column is not padded."""
    rows = [("theme", "pair", "fg / bg", "ratio", "need", "", "rendered by")]
    rows += [
        (
            r.theme,
            r.pair.name,
            f"{r.pair.fg} / {' + '.join(map(str, r.pair.bg))}",
            f"{r.ratio:.2f}",
            f"{r.pair.kind.minimum:g} ({r.pair.kind.criterion})",
            "ok" if r.passed else "FAIL",
            r.pair.source,
        )
        for r in results
    ]
    widths = [max(map(len, column)) for column in zip(*rows, strict=True)]
    return "\n".join(
        "  ".join(cell.ljust(width) for cell, width in zip(row[:-1], widths, strict=False)) + "  " + row[-1]
        for row in rows
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--css", type=Path, default=DEFAULT_CSS, help=f"stylesheet (default: {DEFAULT_CSS})")
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="THEME:TOKEN=oklch(...)",
        help="try a token value without editing the stylesheet; repeatable",
    )
    args = parser.parse_args(argv)
    try:
        themes = read_tokens(args.css.read_text(encoding="utf-8"))
        apply_overrides(themes, args.set)
    except (OSError, ValueError) as error:
        print(f"contrast.py: {error}", file=sys.stderr)
        return 2
    results = evaluate(themes)
    print(report(results))
    if failed := sum(not r.passed for r in results):
        print(f"\n{failed} pair(s) below the WCAG minimum", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
