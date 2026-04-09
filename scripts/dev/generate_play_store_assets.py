from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "play-store-assets"

BG = "#F4F6F8"
SURFACE = "#FFFFFF"
SURFACE_ALT = "#EBEFF3"
HERO = "#2D6CF6"
HERO_ACCENT = "#DCE7FF"
INK = "#10181F"
INK_MUTED = "#62727F"
LINE = "#D9E1E7"
SUCCESS = "#247E65"

SEGOE = Path(r"C:\WINDOWS\Fonts\segoeui.ttf")
SEGOE_BOLD = Path(r"C:\WINDOWS\Fonts\segoeuib.ttf")
SEGOE_SEMIBOLD = Path(r"C:\WINDOWS\Fonts\seguisb.ttf")


def font(path: Path, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(path), size)


def round_rect(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    radius: int,
    fill: str,
    outline: str | None = None,
    width: int = 1,
) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def speech_bubble(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    radius: int,
    fill: str,
) -> None:
    left, top, right, bottom = box
    draw.rounded_rectangle(box, radius=radius, fill=fill)
    tail = [
        (left + 72, bottom - 4),
        (left + 132, bottom - 4),
        (left + 94, bottom + 38),
    ]
    draw.polygon(tail, fill=fill)


def speech_bubble_outline(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    radius: int,
    fill: str,
    outline: str,
    width: int,
) -> None:
    left, top, right, bottom = box
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)
    tail = [
        (left + 86, bottom - 5),
        (left + 132, bottom - 5),
        (left + 102, bottom + 34),
    ]
    draw.polygon(tail, fill=fill, outline=outline)


def shield(draw: ImageDraw.ImageDraw, center: tuple[int, int], width: int, height: int, fill: str) -> None:
    cx, cy = center
    top = cy - height // 2
    pts = [
        (cx - width * 0.42, top + height * 0.12),
        (cx, top),
        (cx + width * 0.42, top + height * 0.12),
        (cx + width * 0.34, top + height * 0.58),
        (cx, top + height),
        (cx - width * 0.34, top + height * 0.58),
    ]
    draw.polygon([(int(x), int(y)) for x, y in pts], fill=fill)


def shield_points(center: tuple[int, int], width: int, height: int) -> list[tuple[int, int]]:
    cx, cy = center
    top = cy - height // 2
    pts = [
        (cx - width * 0.42, top + height * 0.12),
        (cx, top),
        (cx + width * 0.42, top + height * 0.12),
        (cx + width * 0.34, top + height * 0.58),
        (cx, top + height),
        (cx - width * 0.34, top + height * 0.58),
    ]
    return [(int(x), int(y)) for x, y in pts]


def draw_check(
    draw: ImageDraw.ImageDraw,
    p1: tuple[int, int],
    p2: tuple[int, int],
    p3: tuple[int, int],
    fill: str,
    width: int,
) -> None:
    draw.line([p1, p2, p3], fill=fill, width=width, joint="curve")


def make_icon() -> Path:
    img = Image.new("RGBA", (512, 512), HERO)
    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)

    od.ellipse((36, 24, 270, 258), fill=(255, 255, 255, 22))
    od.ellipse((308, 316, 478, 486), fill=(255, 255, 255, 16))
    img = Image.alpha_composite(img, overlay)

    bubble_shadow = Image.new("RGBA", img.size, (0, 0, 0, 0))
    bsd = ImageDraw.Draw(bubble_shadow)
    round_rect(bsd, (92, 94, 420, 408), 96, (16, 24, 31, 42))
    bubble_shadow = bubble_shadow.filter(ImageFilter.GaussianBlur(18))
    img = Image.alpha_composite(img, bubble_shadow)

    draw = ImageDraw.Draw(img)
    round_rect(draw, (84, 84, 412, 398), 92, SURFACE, outline=HERO_ACCENT, width=3)
    round_rect(draw, (164, 74, 332, 118), 22, SURFACE, outline=HERO_ACCENT, width=3)
    round_rect(draw, (142, 144, 354, 330), 44, "#F8FAFD", outline=HERO_ACCENT, width=6)
    round_rect(draw, (164, 166, 332, 308), 34, HERO_ACCENT)
    draw.ellipse((210, 204, 286, 280), fill=HERO)
    draw.ellipse((226, 220, 270, 264), fill=SURFACE)
    draw.line((248, 176, 248, 234), fill=HERO, width=10)
    draw.line((248, 250, 248, 298), fill=HERO, width=10)
    draw.line((220, 242, 276, 242), fill=HERO, width=10)
    draw.line((206, 206, 226, 226), fill=HERO, width=8)
    draw.line((290, 206, 270, 226), fill=HERO, width=8)
    draw.line((206, 278, 226, 258), fill=HERO, width=8)
    draw.line((290, 278, 270, 258), fill=HERO, width=8)
    draw.ellipse((176, 184, 192, 200), fill=HERO)
    draw.ellipse((304, 184, 320, 200), fill=HERO)
    draw.ellipse((176, 274, 192, 290), fill=HERO)
    draw.ellipse((304, 274, 320, 290), fill=HERO)

    out = OUT_DIR / "pqmsg-play-icon-512.png"
    img.save(out)
    return out


def make_feature() -> Path:
    img = Image.new("RGBA", (1024, 500), BG)
    draw = ImageDraw.Draw(img)

    draw.rectangle((0, 0, 1024, 500), fill=BG)
    draw.ellipse((-140, -110, 448, 320), fill=HERO_ACCENT)
    draw.ellipse((726, -64, 1110, 288), fill="#EAF1FF")
    draw.ellipse((604, 274, 1110, 748), fill="#EEF3F7")
    draw.ellipse((452, 344, 742, 624), fill="#F0F5FF")

    card_shadow = Image.new("RGBA", img.size, (0, 0, 0, 0))
    csd = ImageDraw.Draw(card_shadow)
    round_rect(csd, (576, 48, 944, 432), 42, (16, 24, 31, 34))
    card_shadow = card_shadow.filter(ImageFilter.GaussianBlur(24))
    img = Image.alpha_composite(img, card_shadow)
    draw = ImageDraw.Draw(img)

    round_rect(draw, (568, 42, 936, 426), 42, SURFACE, outline=LINE, width=2)
    draw.ellipse((596, 82, 642, 128), fill=SURFACE_ALT, outline=LINE, width=2)
    draw.line((610, 105, 628, 105), fill=INK_MUTED, width=4)
    draw.line((610, 105, 618, 97), fill=INK_MUTED, width=4)
    draw.line((610, 105, 618, 113), fill=INK_MUTED, width=4)
    draw.text((662, 86), "eve", fill=INK, font=font(SEGOE_SEMIBOLD, 30))
    draw.text((662, 122), "offline • review identity", fill=INK_MUTED, font=font(SEGOE, 18))
    draw.ellipse((866, 82, 912, 128), fill=SURFACE_ALT, outline=LINE, width=2)
    draw.ellipse((885, 100, 889, 104), fill=INK_MUTED)
    draw.ellipse((885, 108, 889, 112), fill=INK_MUTED)
    draw.ellipse((885, 116, 889, 120), fill=INK_MUTED)

    round_rect(draw, (596, 150, 908, 366), 28, SURFACE, outline=LINE, width=2)
    round_rect(draw, (714, 168, 790, 196), 14, SURFACE_ALT)
    draw.text((734, 173), "Today", fill=INK_MUTED, font=font(SEGOE_SEMIBOLD, 16))

    round_rect(draw, (616, 210, 726, 264), 20, SURFACE, outline=LINE, width=2)
    draw.text((634, 224), "Hello Bob!", fill=INK, font=font(SEGOE_SEMIBOLD, 17))
    draw.text((634, 246), "10:15 PM", fill=INK_MUTED, font=font(SEGOE, 12))

    round_rect(draw, (748, 246, 860, 302), 22, HERO)
    draw.text((770, 260), "Hi Alice!", fill=SURFACE, font=font(SEGOE_SEMIBOLD, 17))
    draw.text((770, 284), "10:17 PM", fill="#DCE7FF", font=font(SEGOE, 12))

    round_rect(draw, (616, 316, 846, 362), 22, SURFACE, outline=LINE, width=2)
    draw.text((636, 331), "Secure and exciting!", fill=INK, font=font(SEGOE_SEMIBOLD, 17))

    round_rect(draw, (600, 378, 906, 414), 18, SURFACE, outline=LINE, width=2)
    round_rect(draw, (612, 386, 644, 406), 10, SURFACE_ALT)
    draw.line((622, 396, 634, 396), fill=INK_MUTED, width=3)
    draw.line((628, 390, 628, 402), fill=INK_MUTED, width=3)
    round_rect(draw, (658, 384, 848, 408), 12, SURFACE, outline=LINE, width=2)
    draw.text((680, 389), "Message", fill=INK_MUTED, font=font(SEGOE, 18))
    round_rect(draw, (860, 384, 894, 408), 12, HERO)
    draw.polygon([(872, 390), (886, 396), (872, 402), (876, 396)], fill=SURFACE)

    icon = Image.open(OUT_DIR / "pqmsg-play-icon-512.png").resize((96, 96), Image.LANCZOS)
    img.alpha_composite(icon, (84, 82))

    draw.text((86, 154), "PQmsg", fill=INK, font=font(SEGOE_BOLD, 72))
    draw.text(
        (86, 236),
        "Private messaging with\npost-quantum security",
        fill=INK,
        font=font(SEGOE_SEMIBOLD, 36),
        spacing=8,
    )
    draw.text(
        (86, 368),
        "Direct chats, private groups, local key control.",
        fill=INK_MUTED,
        font=font(SEGOE, 26),
    )

    out = OUT_DIR / "pqmsg-feature-graphic-1024x500.png"
    img.save(out)
    return out


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    icon_path = make_icon()
    feature_path = make_feature()
    print(icon_path)
    print(feature_path)


if __name__ == "__main__":
    main()
