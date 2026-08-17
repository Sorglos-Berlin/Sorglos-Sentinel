"""Generate owned Windows icon and executable version metadata."""

from __future__ import annotations

import argparse
import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

COLORS = [(255, 169, 55), (255, 70, 105), (220, 42, 158), (98, 54, 235), (32, 75, 255)]


def color_at(position: float) -> tuple[int, int, int, int]:
    scaled = max(0.0, min(0.9999, position)) * (len(COLORS) - 1)
    index, fraction = int(scaled), scaled % 1
    left, right = COLORS[index], COLORS[index + 1]
    return tuple(round(left[i] + (right[i] - left[i]) * fraction) for i in range(3)) + (255,)


def gradient(size: int) -> Image.Image:
    image = Image.new("RGBA", (size, size))
    pixels = image.load()
    for y in range(size):
        for x in range(size):
            angle = (math.atan2(y - size / 2, x - size / 2) + math.pi) / (2 * math.pi)
            pixels[x, y] = color_at((angle + .12) % 1)
    return image


def font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [Path("C:/Windows/Fonts/seguisb.ttf"), Path("C:/Windows/Fonts/arialbd.ttf")]
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def create_icon(path: Path) -> None:
    size = 512
    canvas = Image.new("RGBA", (size, size), (7, 20, 34, 255))
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle((8, 8, size - 8, size - 8), radius=105, fill=(7, 20, 34, 255))
    colors = gradient(size)
    ring = Image.new("L", (size, size)); mask = ImageDraw.Draw(ring)
    mask.ellipse((74, 74, 438, 438), fill=255); mask.ellipse((112, 112, 400, 400), fill=0)
    canvas.alpha_composite(Image.composite(colors, Image.new("RGBA", canvas.size), ring))
    letter_mask = Image.new("L", (size, size)); letter = ImageDraw.Draw(letter_mask)
    selected_font = font(270); box = letter.textbbox((0, 0), "S", font=selected_font)
    x = (size - (box[2] - box[0])) / 2 - box[0]
    y = (size - (box[3] - box[1])) / 2 - box[1] - 2
    letter.text((x, y), "S", font=selected_font, fill=255)
    canvas.alpha_composite(Image.composite(colors, Image.new("RGBA", canvas.size), letter_mask))
    path.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(path, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


def create_version_file(path: Path, version: str) -> None:
    parts = [int(value) for value in version.split(".")[:3] if value.isdigit()]
    numeric = tuple((parts + [0, 0, 0, 0])[:4])
    content = f"""VSVersionInfo(ffi=FixedFileInfo(filevers={numeric}, prodvers={numeric}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)), kids=[StringFileInfo([StringTable('040704B0', [StringStruct('CompanyName', 'Sorglos-Apps'), StringStruct('FileDescription', 'Network Sentinel'), StringStruct('FileVersion', '{version}'), StringStruct('InternalName', 'Network Sentinel'), StringStruct('LegalCopyright', 'Copyright 2026 Sorglos-Apps'), StringStruct('OriginalFilename', 'Network Sentinel.exe'), StringStruct('ProductName', 'Network Sentinel'), StringStruct('ProductVersion', '{version}')])]), VarFileInfo([VarStruct('Translation', [1031, 1200])])])"""
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--icon", type=Path, required=True)
    parser.add_argument("--version-file", type=Path, required=True)
    args = parser.parse_args()
    create_icon(args.icon)
    create_version_file(args.version_file, args.version)
