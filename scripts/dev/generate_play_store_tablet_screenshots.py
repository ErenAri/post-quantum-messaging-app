from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageOps


ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT / "Screenshots"
OUT_DIR = ROOT / "play-store-assets" / "tablet-screenshots"

BG = "#F4F6F8"
SURFACE = "#FFFFFF"
LINE = "#D9E1E7"
HERO = "#2D6CF6"
HERO_ACCENT = "#DCE7FF"
INK_MUTED = "#62727F"

PHONE_SCREENS = [
    "android-03-inbox.png",
    "android-04-direct-chat.png",
    "android-06-people.png",
    "android-07-privacy-account.png",
]


def round_rect(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    radius: int,
    fill: str,
    outline: str | None = None,
    width: int = 1,
) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def make_tablet_frame(size: tuple[int, int], image: Image.Image) -> Image.Image:
    canvas = Image.new("RGBA", size, BG)
    draw = ImageDraw.Draw(canvas)
    w, h = size

    draw.ellipse((-120, -80, 420, 320), fill=HERO_ACCENT)
    draw.ellipse((w - 300, h - 240, w + 120, h + 120), fill="#EEF3F7")

    shadow = Image.new("RGBA", size, (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    round_rect(sd, (80, 44, w - 80, h - 44), 40, (16, 24, 31, 34))
    shadow = shadow.filter(ImageFilter.GaussianBlur(22))
    canvas.alpha_composite(shadow)

    draw = ImageDraw.Draw(canvas)
    round_rect(draw, (72, 36, w - 72, h - 36), 40, SURFACE, outline=LINE, width=2)
    round_rect(draw, (104, 66, w - 104, 106), 20, HERO_ACCENT)
    draw.ellipse((w // 2 - 18, 78, w // 2 + 18, 114), fill=HERO)
    draw.ellipse((w // 2 - 6, 90, w // 2 + 6, 102), fill=SURFACE)

    inner_x1, inner_y1 = 132, 138
    inner_x2, inner_y2 = w - 132, h - 92
    inner_w = inner_x2 - inner_x1
    inner_h = inner_y2 - inner_y1

    framed = ImageOps.contain(image.convert("RGBA"), (inner_w, inner_h), Image.LANCZOS)
    offset_x = inner_x1 + (inner_w - framed.width) // 2
    offset_y = inner_y1 + (inner_h - framed.height) // 2
    canvas.alpha_composite(framed, (offset_x, offset_y))

    draw = ImageDraw.Draw(canvas)
    round_rect(draw, (w // 2 - 90, h - 70, w // 2 + 90, h - 52), 9, "#E9EEF4")
    return canvas


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name in PHONE_SCREENS:
        src = SRC_DIR / name
        if not src.exists():
            continue
        img = Image.open(src)
        seven = make_tablet_frame((1600, 2560), img)
        ten = make_tablet_frame((1920, 2560), img)
        stem = Path(name).stem
        seven.save(OUT_DIR / f"{stem}-7in.png")
        ten.save(OUT_DIR / f"{stem}-10in.png")
        print(OUT_DIR / f"{stem}-7in.png")
        print(OUT_DIR / f"{stem}-10in.png")


if __name__ == "__main__":
    main()
