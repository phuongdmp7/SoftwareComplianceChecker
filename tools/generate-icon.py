#!/usr/bin/env python3
"""Generate the application icon.

The icon is a shield carrying a check mark: a shield reads as audit and policy, and the
check reads as verification. Both shapes stay legible at 16x16, which is the size that
actually decides whether an icon works.

The artwork is generated rather than committed as an opaque binary so the colours and
proportions can be adjusted and the result reproduced exactly.

Usage:
    python3 tools/generate-icon.py

Requires Pillow.
"""

from __future__ import annotations

import pathlib

from PIL import Image, ImageDraw

# Drawn large and downsampled, which anti-aliases far better than drawing small.
CANVAS = 1024

# Sizes Windows picks between. 16 and 32 carry the taskbar and title bar; 256 is the
# Explorer preview.
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]

SHIELD_TOP = (0x33, 0x9A, 0xF0, 0xFF)
SHIELD_BOTTOM = (0x15, 0x5F, 0xC4, 0xFF)
CHECK = (0xFF, 0xFF, 0xFF, 0xFF)

OUTPUT_ICO = pathlib.Path("src/SoftwareComplianceChecker.App/Assets/app.ico")
OUTPUT_PNG = pathlib.Path("docs/icon.png")


def quadratic(start, control, end, steps=80):
    """Points along a quadratic bezier, used for the shield's lower curves."""
    points = []
    for i in range(steps + 1):
        t = i / steps
        inv = 1 - t
        x = inv * inv * start[0] + 2 * inv * t * control[0] + t * t * end[0]
        y = inv * inv * start[1] + 2 * inv * t * control[1] + t * t * end[1]
        points.append((x, y))
    return points


def shield_outline(size):
    """The shield silhouette, in pixels, for a square canvas of the given size."""
    def p(x, y):
        return (x * size, y * size)

    left_top = p(0.10, 0.13)
    left_straight = p(0.10, 0.52)
    bottom_point = p(0.50, 0.95)
    right_straight = p(0.90, 0.52)
    right_top = p(0.90, 0.13)

    outline = [left_top, left_straight]
    outline += quadratic(left_straight, p(0.12, 0.80), bottom_point)
    outline += quadratic(bottom_point, p(0.88, 0.80), right_straight)
    outline += [right_top]

    return outline


def vertical_gradient(size, top, bottom):
    """A top-to-bottom gradient, giving the shield a little depth."""
    gradient = Image.new("RGBA", (1, size))
    pixels = gradient.load()

    for y in range(size):
        t = y / max(size - 1, 1)
        pixels[0, y] = tuple(
            round(top[channel] + (bottom[channel] - top[channel]) * t) for channel in range(4)
        )

    return gradient.resize((size, size), Image.Resampling.NEAREST)


def render(size):
    """Render the icon at the given square size."""
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).polygon(shield_outline(size), fill=255)

    image.paste(vertical_gradient(size, SHIELD_TOP, SHIELD_BOTTOM), (0, 0), mask)

    draw = ImageDraw.Draw(image)

    def p(x, y):
        return (x * size, y * size)

    # A single thick polyline with round joints reads more cleanly when scaled down than
    # a filled check-mark polygon, whose thin tips disappear at 16 pixels.
    draw.line(
        [p(0.30, 0.49), p(0.44, 0.63), p(0.71, 0.33)],
        fill=CHECK,
        width=round(size * 0.11),
        joint="curve",
    )

    radius = size * 0.055
    for x, y in ((0.30, 0.49), (0.71, 0.33)):
        centre = p(x, y)
        draw.ellipse(
            [centre[0] - radius, centre[1] - radius, centre[0] + radius, centre[1] + radius],
            fill=CHECK,
        )

    return image


def main():
    master = render(CANVAS)

    OUTPUT_ICO.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PNG.parent.mkdir(parents=True, exist_ok=True)

    # Each size is downsampled from the master rather than letting the ICO encoder scale,
    # which produces noticeably crisper small sizes.
    frames = [master.resize((s, s), Image.Resampling.LANCZOS) for s in ICO_SIZES]

    frames[-1].save(OUTPUT_ICO, format="ICO", sizes=[(s, s) for s in ICO_SIZES], append_images=frames)
    master.resize((256, 256), Image.Resampling.LANCZOS).save(OUTPUT_PNG, format="PNG")

    print(f"Wrote {OUTPUT_ICO} ({', '.join(f'{s}x{s}' for s in ICO_SIZES)})")
    print(f"Wrote {OUTPUT_PNG} (256x256)")


if __name__ == "__main__":
    main()
