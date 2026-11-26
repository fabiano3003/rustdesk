"""Gera os icones e o logo do Suporte-Telesys a partir de icon-source.png e logo-source.png.

Uso (na raiz do repositorio, com Pillow instalado):
    python res/telesys/gen_branding.py
"""
import glob
import os

from PIL import Image

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HERE = os.path.dirname(os.path.abspath(__file__))


def p(*parts):
    return os.path.join(ROOT, *parts)


src = Image.open(os.path.join(HERE, "icon-source.png")).convert("RGBA")
logo = Image.open(os.path.join(HERE, "logo-source.png")).convert("RGBA")


def sized(size):
    return src.resize((size, size), Image.LANCZOS)


def padded(size, ratio, bg=None):
    canvas = Image.new("RGBA", (size, size), bg or (0, 0, 0, 0))
    inner = round(size * ratio)
    off = (size - inner) // 2
    canvas.alpha_composite(sized(inner), (off, off))
    return canvas


def on_white(im):
    bg = Image.new("RGBA", im.size, (255, 255, 255, 255))
    bg.alpha_composite(im)
    return bg.convert("RGB")


def save_ico(path, sizes):
    big = sized(max(sizes))
    big.save(path, format="ICO", sizes=[(s, s) for s in sizes])


def stat_logo(size):
    # Icone de notificacao do Android: so silhueta branca (partes brancas do icone).
    im = sized(size)
    out = Image.new("LA", im.size, (255, 0))
    px, po = im.load(), out.load()
    for y in range(size):
        for x in range(size):
            r, g, b, a = px[x, y]
            if a > 128 and min(r, g, b) > 200:
                po[x, y] = (255, 255)
    return out


# Desktop
sized(1024).save(p("res", "icon.png"))
for s, name in [(32, "32x32.png"), (64, "64x64.png"), (128, "128x128.png"), (256, "128x128@2x.png")]:
    sized(s).save(p("res", name))
padded(1024, 0.82).save(p("res", "mac-icon.png"))
ico_sizes = [16, 24, 32, 48, 64, 128, 256]
save_ico(p("res", "icon.ico"), ico_sizes)
save_ico(p("flutter", "windows", "runner", "resources", "app_icon.ico"), ico_sizes)
save_ico(p("res", "tray-icon.ico"), [16, 24, 32])

# Assets do Flutter (icone pequeno das telas e logo da tela inicial, max 300x60)
sized(256).save(p("flutter", "assets", "icon.png"))
logo.save(p("flutter", "assets", "logo.png"))

# Android
dens = {"mdpi": 1, "hdpi": 1.5, "xhdpi": 2, "xxhdpi": 3, "xxxhdpi": 4}
for d, k in dens.items():
    base = p("flutter", "android", "app", "src", "main", "res", f"mipmap-{d}")
    sized(round(48 * k)).save(os.path.join(base, "ic_launcher.png"))
    sized(round(48 * k)).save(os.path.join(base, "ic_launcher_round.png"))
    padded(round(108 * k), 0.62).save(os.path.join(base, "ic_launcher_foreground.png"))
    stat_logo(round(24 * k)).save(os.path.join(base, "ic_stat_logo.png"))

# iOS (sem transparencia)
for f in glob.glob(p("flutter", "ios", "Runner", "Assets.xcassets", "AppIcon.appiconset", "*.png")):
    w = Image.open(f).size[0]
    on_white(sized(w)).save(f)

print("ok")
