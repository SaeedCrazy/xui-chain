"""Pingo brand kit: SVG sources, rendered to PNG with rsvg-convert."""
import os, subprocess
OUT = "/root/vpn/brand/kit"
N950, N900, N800 = "#060B18", "#0B1430", "#121D3D"
ICE, ICE3, AQUA, AUR, AUR3, BEAK, SNOW, MIST = "#38BDF8", "#7DD3FC", "#5EEAD4", "#8B5CF6", "#A78BFA", "#FF8A3D", "#F8FAFC", "#94A3B8"
DISPLAY, BODY = "Capsule", "Vazirmatn"

DEFS = f"""
<linearGradient id="ice" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{AQUA}"/><stop offset=".5" stop-color="{ICE}"/><stop offset="1" stop-color="{AUR}"/></linearGradient>
<linearGradient id="iceh" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{AQUA}"/><stop offset=".55" stop-color="{ICE}"/><stop offset="1" stop-color="{AUR3}"/></linearGradient>
<linearGradient id="body" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#22304F"/><stop offset="1" stop-color="#0D1530"/></linearGradient>
<linearGradient id="belly" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#FFFFFF"/><stop offset="1" stop-color="#DCEBFA"/></linearGradient>
<linearGradient id="beak" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#FFB27A"/><stop offset="1" stop-color="{BEAK}"/></linearGradient>
<linearGradient id="glass" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#FFFFFF" stop-opacity=".16"/><stop offset=".45" stop-color="#FFFFFF" stop-opacity=".05"/><stop offset="1" stop-color="#FFFFFF" stop-opacity=".02"/></linearGradient>
<linearGradient id="rim" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#FFFFFF" stop-opacity=".55"/><stop offset=".5" stop-color="#FFFFFF" stop-opacity=".08"/><stop offset="1" stop-color="{ICE3}" stop-opacity=".45"/></linearGradient>
<linearGradient id="night" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{N800}"/><stop offset=".55" stop-color="{N900}"/><stop offset="1" stop-color="{N950}"/></linearGradient>
<filter id="blur60" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="60"/></filter>
<filter id="blur30" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="30"/></filter>
<filter id="soft" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="8"/></filter>
"""

def penguin(cx, cy, s):
    """The mascot: round, friendly, a ping above its head. s = scale (1 = 256 px tall)."""
    g = f'<g transform="translate({cx},{cy}) scale({s})">'
    g += f'<ellipse cx="0" cy="118" rx="70" ry="10" fill="#000" opacity=".35" filter="url(#soft)"/>'
    g += '<g fill="none" stroke="url(#iceh)" stroke-linecap="round">'
    g += '<path d="M-80 -150 A104 104 0 0 1 80 -150" stroke-width="15" opacity=".45"/>'
    g += '<path d="M-48 -124 A62 62 0 0 1 48 -124" stroke-width="15" opacity=".9"/></g>'
    g += '<circle cx="0" cy="-102" r="11" fill="url(#ice)"/>'
    g += '<ellipse cx="0" cy="22" rx="92" ry="104" fill="url(#body)"/>'
    g += '<path d="M-90 4 Q-122 46 -96 92 Q-82 62 -78 30 Z" fill="#0D1530"/><path d="M90 4 Q122 46 96 92 Q82 62 78 30 Z" fill="#0D1530"/>'
    g += '<ellipse cx="0" cy="40" rx="62" ry="80" fill="url(#belly)"/>'
    g += '<ellipse cx="-26" cy="-22" rx="13" ry="14" fill="#fff"/><ellipse cx="26" cy="-22" rx="13" ry="14" fill="#fff"/>'
    g += '<circle cx="-23" cy="-20" r="7" fill="#0B1430"/><circle cx="23" cy="-20" r="7" fill="#0B1430"/>'
    g += '<circle cx="-21" cy="-23" r="2.5" fill="#fff"/><circle cx="25" cy="-23" r="2.5" fill="#fff"/>'
    g += '<path d="M-15 -4 Q0 -14 15 -4 L0 15 Z" fill="url(#beak)"/>'
    g += '<ellipse cx="-44" cy="6" rx="9" ry="5.5" fill="#FB7185" opacity=".45"/><ellipse cx="44" cy="6" rx="9" ry="5.5" fill="#FB7185" opacity=".45"/>'
    g += '<ellipse cx="-30" cy="122" rx="26" ry="9" fill="url(#beak)"/><ellipse cx="30" cy="122" rx="26" ry="9" fill="url(#beak)"/>'
    g += '<path d="M-56 -40 Q-34 -66 -4 -72" stroke="#fff" stroke-opacity=".14" stroke-width="9" fill="none" stroke-linecap="round"/>'
    return g + '</g>'

def aurora(w, h, spots):
    return "".join(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{c}" opacity="{o}" filter="url(#blur60)"/>' for x, y, r, c, o in spots)

def glass(x, y, w, h, r):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="url(#glass)"/>'
            f'<rect x="{x+.75}" y="{y+.75}" width="{w-1.5}" height="{h-1.5}" rx="{r}" fill="none" stroke="url(#rim)" stroke-width="1.5"/>')

def svg(w, h, body):
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}"><defs>{DEFS}</defs>{body}</svg>'

def pill(x, y, w, h, text, fill=None, color=SNOW, size=24, glow=None):
    out = ""
    if glow:
        out += f'<rect x="{x}" y="{y+8}" width="{w}" height="{h}" rx="{h/2}" fill="{glow}" opacity=".55" filter="url(#blur30)"/>'
    out += (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h/2}" fill="{fill}"/>' if fill else glass(x, y, w, h, h / 2))
    out += f'<rect x="{x+1}" y="{y+1}" width="{w-2}" height="{h/2}" rx="{h/2-1}" fill="#fff" opacity=".10"/>'
    out += f'<text x="{x+w/2}" y="{y+h/2+size*0.36}" font-family="{BODY}" font-weight="800" font-size="{size}" fill="{color}" text-anchor="middle">{text}</text>'
    if glow and not fill:
        out += f'<circle cx="{x+h/2+4}" cy="{y+h/2}" r="7" fill="{glow}"/>'
    return out

def write(name, w, h, body, scale=1):
    path = os.path.join(OUT, name + ".svg")
    open(path, "w").write(svg(w, h, body))
    subprocess.run(["rsvg-convert", "-w", str(int(w * scale)), "-h", str(int(h * scale)), path, "-o", path[:-4] + ".png"], check=True)

# 1. app icon / bot avatar
icon = (f'<rect width="1024" height="1024" rx="232" fill="url(#night)"/>'
        + aurora(1024, 1024, [(260, 240, 260, AUR, .55), (820, 300, 240, ICE, .55), (560, 900, 300, AQUA, .30)])
        + glass(96, 96, 832, 832, 190) + penguin(512, 560, 2.15))
write("icon", 1024, 1024, icon, .625)   # 640 px avatar

# 2. lockups
lock = (f'<rect width="1600" height="640" fill="url(#night)"/>' + aurora(1600, 640, [(300, 200, 260, AUR, .5), (1300, 420, 280, ICE, .45)])
        + f'<g transform="translate(140,120)">' + f'<rect width="400" height="400" rx="92" fill="url(#night)"/>' + glass(0, 0, 400, 400, 92)
        + penguin(200, 222, .98) + '</g>'
        + f'<text x="1460" y="360" font-family="{DISPLAY}" font-size="230" fill="{SNOW}" text-anchor="end">پینگو</text>'
        + f'<text x="1460" y="460" font-family="{BODY}" font-weight="800" font-size="62" fill="url(#iceh)" text-anchor="end" letter-spacing="18">PINGO</text>')
write("lockup", 1600, 640, lock, .75)

# 3. banner (bot menu, 2:1)
ban = (f'<rect width="1280" height="640" fill="url(#night)"/>'
       + aurora(1280, 640, [(980, 160, 220, AUR, .55), (1180, 520, 220, ICE, .55), (160, 600, 260, AQUA, .25), (520, 60, 160, ICE3, .18)])
       + glass(60, 60, 1160, 520, 64)
       + f'<circle cx="955" cy="330" r="190" fill="{ICE}" opacity=".18" filter="url(#blur30)"/>'
       + penguin(955, 345, 1.18)
       + f'<text x="740" y="270" font-family="{DISPLAY}" font-size="150" fill="{SNOW}" text-anchor="end">پینگو</text>'
       + f'<text x="740" y="352" font-family="{BODY}" font-weight="700" font-size="44" fill="url(#iceh)" text-anchor="end">اینترنت آزاد، سریع و بی‌دردسر</text>'
       + pill(486, 410, 254, 72, "پینگ پایین", glow=ICE, size=26)
       + pill(216, 410, 254, 72, "امن و پایدار", glow=AUR, size=26)
       + f'<text x="130" y="530" font-family="{BODY}" font-weight="700" font-size="24" fill="{MIST}" letter-spacing="8">PINGO • VPN</text>')
write("banner", 1280, 640, ban)

# 4. palette sheet
sw = [("شب قطبی", N950, SNOW), ("شب", N900, SNOW), ("شب روشن", N800, SNOW), ("یخچال", ICE, N950), ("یخچال روشن", ICE3, N950),
      ("آبی دریایی", AQUA, N950), ("شفق", AUR, SNOW), ("شفق روشن", AUR3, N950), ("منقار", BEAK, N950), ("برف", SNOW, N950), ("مه", MIST, N950)]
pal = f'<rect width="1600" height="1000" fill="url(#night)"/>' + aurora(1600, 1000, [(1400, 120, 260, AUR, .4), (200, 900, 300, ICE, .35)])
pal += f'<text x="1520" y="140" font-family="{DISPLAY}" font-size="96" fill="{SNOW}" text-anchor="end">پالت رنگ پینگو</text>'
pal += f'<text x="1520" y="200" font-family="{BODY}" font-weight="500" font-size="30" fill="{MIST}" text-anchor="end">شب قطبی + یخ + شفق + یه نقطه‌ی گرم نارنجی، مثل منقار پنگوئن</text>'
for i, (name, hexc, ink) in enumerate(sw):
    col, row = i % 4, i // 4
    x, y = 1520 - (col + 1) * 350 + 10, 260 + row * 230
    pal += f'<rect x="{x}" y="{y}" width="330" height="200" rx="36" fill="{hexc}"/>' + glass(x, y, 330, 200, 36)
    pal += f'<text x="{x+300}" y="{y+70}" font-family="{BODY}" font-weight="800" font-size="34" fill="{ink}" text-anchor="end">{name}</text>'
    pal += f'<text x="{x+300}" y="{y+165}" font-family="DejaVu Sans Mono" font-size="28" fill="{ink}" text-anchor="end">{hexc}</text>'
pal += f'<rect x="80" y="950" width="1440" height="14" rx="7" fill="url(#ice)"/>'
write("palette", 1600, 1000, pal, .75)

# 5. typography + UI sheet (glass components in the brand colours)
ui = f'<rect width="1600" height="1100" fill="url(#night)"/>' + aurora(1600, 1100, [(300, 260, 300, AUR, .5), (1300, 800, 320, ICE, .45), (900, 120, 200, AQUA, .25)])
ui += f'<text x="1520" y="150" font-family="{DISPLAY}" font-size="110" fill="{SNOW}" text-anchor="end">کپسول، برای تیترها</text>'
ui += f'<text x="1520" y="225" font-family="{BODY}" font-weight="500" font-size="36" fill="{MIST}" text-anchor="end">وزیرمتن برای متن‌ها؛ خوانا، گرد و صمیمی. اعداد فارسی: ۰۱۲۳۴۵۶۷۸۹</text>'
ui += glass(820, 300, 700, 420, 56)
ui += f'<text x="1460" y="380" font-family="{BODY}" font-weight="800" font-size="34" fill="{SNOW}" text-anchor="end">‏۳۰ گیگ ‏•‏ ۳۰ روزه‏</text>'
ui += f'<text x="1460" y="470" font-family="{DISPLAY}" font-size="84" fill="url(#iceh)" text-anchor="end">۳۳۰٬۰۰۰</text>'
ui += f'<text x="1460" y="520" font-family="{BODY}" font-weight="500" font-size="26" fill="{MIST}" text-anchor="end">تومان ‏•‏ مناسب گوشی و لپ‌تاپ</text>'
ui += pill(880, 600, 580, 84, "خرید با یه لمس", fill="url(#iceh)", color=N950, size=30, glow=ICE)
ui += pill(420, 320, 340, 84, "تمدید", fill="url(#ice)", color=N950, size=30, glow=AUR)
ui += pill(80, 320, 320, 84, "کیف پول", size=30)
ui += pill(420, 430, 340, 84, "پلن دلخواه", size=30)
ui += pill(80, 430, 320, 84, "پشتیبانی", size=30)
ui += pill(80, 560, 680, 84, "تست رایگان ۱ روزه", fill=BEAK, color=N950, size=30, glow=BEAK)
ui += glass(80, 760, 1440, 260, 56)
ui += f'<text x="1460" y="840" font-family="{BODY}" font-weight="800" font-size="34" fill="{SNOW}" text-anchor="end">سرویس من ‏•‏ <tspan fill="#34D399">● فعال</tspan></text>'
ui += f'<rect x="140" y="880" width="1320" height="22" rx="11" fill="#fff" opacity=".08"/><rect x="560" y="880" width="900" height="22" rx="11" fill="url(#iceh)"/>'
ui += f'<text x="1460" y="960" font-family="{BODY}" font-weight="600" font-size="28" fill="{MIST}" text-anchor="end">‏۲۰٫۵ گیگ از ‏۳۰ گیگ مانده ‏•‏ ۱۸ روز‏</text>'
write("ui-kit", 1600, 1100, ui, .75)
print("ok")

# 6. BotFather description picture, exactly 640x360 (drawn at 1280x720 and scaled)
R = "‏"
desc = (f'<rect width="1280" height="720" fill="url(#night)"/>'
        + aurora(1280, 720, [(1000, 160, 230, AUR, .55), (1180, 600, 240, ICE, .55), (160, 640, 260, AQUA, .25)])
        + glass(56, 56, 1168, 608, 72)
        + f'<circle cx="980" cy="370" r="200" fill="{ICE}" opacity=".16" filter="url(#blur30)"/>'
        + penguin(980, 392, 1.25)
        + f'<text x="760" y="250" font-family="{DISPLAY}" font-size="140" fill="{SNOW}" text-anchor="end">پینگو</text>'
        + f'<text x="760" y="350" font-family="{DISPLAY}" font-size="58" fill="url(#iceh)" text-anchor="end">همراه و رفیق تو</text>'
        + pill(150, 420, 290, 76, "پشتیبانی واقعی", glow=AUR, size=27)
        + pill(470, 420, 290, 76, "اتصال سریع", glow=ICE, size=27)
        + f'<text x="150" y="600" font-family="{BODY}" font-weight="700" font-size="24" fill="{MIST}" letter-spacing="8">PINGO • VPN</text>')
write("botfather-640x360", 1280, 720, desc, .5)

# 7. subscription QR card (EZ fills the white plate with the QR; box = 255,375,570 on 1080x1350)
qr = (f'<rect width="1080" height="1350" fill="url(#night)"/>'
      + aurora(1080, 1350, [(900, 180, 260, AUR, .55), (160, 420, 240, ICE, .45), (980, 1180, 280, AQUA, .30), (120, 1260, 220, AUR3, .25)])
      + glass(48, 48, 984, 1254, 72)
      + f'<text x="540" y="200" font-family="{DISPLAY}" font-size="104" fill="{SNOW}" text-anchor="middle">پینگو</text>'
      + f'<text x="540" y="282" font-family="{DISPLAY}" font-size="46" fill="url(#iceh)" text-anchor="middle">اشتراکت آماده‌ست</text>'
      + f'<rect x="200" y="356" width="680" height="640" rx="64" fill="{ICE}" opacity=".35" filter="url(#blur60)"/>'
      + f'<rect x="230" y="350" width="620" height="620" rx="56" fill="#FFFFFF"/>'
      + f'<rect x="230.75" y="350.75" width="618.5" height="618.5" rx="56" fill="none" stroke="url(#rim)" stroke-width="1.5"/>'
      + f'<text x="540" y="1062" font-family="{BODY}" font-weight="800" font-size="36" fill="{SNOW}" text-anchor="middle">با اپ اسکن کن یا لینک رو کپی کن</text>'
      + f'<text x="540" y="1112" font-family="{BODY}" font-weight="600" font-size="27" fill="{MIST}" text-anchor="middle">لینک اشتراک زیر همین عکسه {R}• لمس کن تا کپی بشه</text>'
      + pill(178, 1150, 220, 64, "Happ", glow=ICE, size=26) + pill(430, 1150, 220, 64, "v2rayNG", size=26) + pill(682, 1150, 220, 64, "Streisand", glow=AUR, size=26)
      + f'<text x="540" y="1268" font-family="{BODY}" font-weight="700" font-size="24" fill="{MIST}" letter-spacing="8" text-anchor="middle">PINGO • VPN</text>')
write("qr-card", 1080, 1350, qr)
# the same card without «اشتراکت آماده‌ست», for every later time the QR is shown
qr_plain = qr.replace(f'<text x="540" y="282" font-family="{DISPLAY}" font-size="46" fill="url(#iceh)" text-anchor="middle">اشتراکت آماده‌ست</text>', "")
qr_plain = qr_plain.replace('<text x="540" y="200" font-family="' + DISPLAY + '" font-size="104"', '<text x="540" y="250" font-family="' + DISPLAY + '" font-size="120"')
assert qr_plain != qr
write("qr-card-plain", 1080, 1350, qr_plain)
logo = (f'<rect x="4" y="4" width="152" height="152" rx="40" fill="#FFFFFF"/>'
        f'<rect x="12" y="12" width="136" height="136" rx="34" fill="url(#night)"/>'
        + penguin(80, 88, .37))
write("qr-logo", 160, 160, logo, .8)
print("qr card ok")
