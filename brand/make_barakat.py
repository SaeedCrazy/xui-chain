"""Pingo «برکت» picture: the mascot with a four-leaf clover, emerald and gold, 1080x1080."""
import math, os, subprocess
exec(open("/root/vpn/brand/make_kit.py").read().split("# 1. app icon")[0])
OUT = "/root/vpn/brand/barakat"
EM9, EM7, EM5, MINT = "#04261A", "#0B4A31", "#10B981", "#6EE7B7"
GOLD, GOLD2, GOLD3 = "#FCD34D", "#F59E0B", "#FDE68A"
EXTRA = f"""
<radialGradient id="bg" cx=".5" cy=".42" r=".75"><stop offset="0" stop-color="#0E5E3C"/><stop offset=".55" stop-color="{EM7}"/><stop offset="1" stop-color="{EM9}"/></radialGradient>
<linearGradient id="goldh" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{GOLD3}"/><stop offset=".5" stop-color="{GOLD}"/><stop offset="1" stop-color="{GOLD2}"/></linearGradient>
<linearGradient id="gold" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{GOLD3}"/><stop offset=".5" stop-color="{GOLD}"/><stop offset="1" stop-color="{GOLD2}"/></linearGradient>
<linearGradient id="leaf" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4ADE80"/><stop offset="1" stop-color="#15803D"/></linearGradient>
<linearGradient id="leaf2" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{MINT}"/><stop offset="1" stop-color="{EM5}"/></linearGradient>
<radialGradient id="halo" cx=".5" cy=".5" r=".5"><stop offset="0" stop-color="{GOLD3}" stop-opacity=".75"/><stop offset=".45" stop-color="{GOLD}" stop-opacity=".25"/><stop offset="1" stop-color="{GOLD}" stop-opacity="0"/></radialGradient>
"""
LEAF = "M0 0 C -34 -8 -56 -40 -38 -62 C -24 -78 -4 -70 0 -52 C 4 -70 24 -78 38 -62 C 56 -40 34 -8 0 0 Z"

def clover(x, y, s, rot=0, fill="url(#leaf)", stem=True, op=1):
    g = f'<g transform="translate({x},{y}) rotate({rot}) scale({s})" opacity="{op}">'
    if stem:
        g += '<path d="M0 0 Q 18 60 6 110" stroke="#15803D" stroke-width="9" fill="none" stroke-linecap="round"/>'
    for a in (0, 90, 180, 270):
        g += f'<path d="{LEAF}" transform="rotate({a})" fill="{fill}" stroke="#065F46" stroke-opacity=".35" stroke-width="2"/>'
        g += f'<path d="M0 -6 L0 -46" transform="rotate({a})" stroke="#FFFFFF" stroke-opacity=".28" stroke-width="3" stroke-linecap="round"/>'
    g += '<circle r="7" fill="#166534"/>'
    return g + '</g>'

def sparkle(x, y, r, c=GOLD3, op=1):
    return (f'<path d="M{x} {y-r} Q{x+r*.18} {y-r*.18} {x+r} {y} Q{x+r*.18} {y+r*.18} {x} {y+r} Q{x-r*.18} {y+r*.18} {x-r} {y} '
            f'Q{x-r*.18} {y-r*.18} {x} {y-r} Z" fill="{c}" opacity="{op}"/>')

def coin(x, y, r, rot=0):
    return (f'<g transform="translate({x},{y}) rotate({rot})"><ellipse rx="{r}" ry="{r*.92}" fill="{GOLD2}"/>'
            f'<ellipse rx="{r*.86}" ry="{r*.8}" fill="url(#gold)"/>'
            f'<text y="{r*.32}" font-family="{BODY}" font-weight="800" font-size="{r*.9}" fill="#B45309" text-anchor="middle">GB</text></g>')

W = H = 1080
body = f'<rect width="{W}" height="{H}" fill="url(#bg)"/>'
body += aurora(W, H, [(860, 160, 240, GOLD, .30), (180, 260, 220, MINT, .30), (900, 940, 260, EM5, .35), (160, 980, 240, GOLD2, .22)])
# soft rays behind the mascot
for i in range(16):
    a = math.radians(i * 22.5)
    x2, y2 = 540 + 760 * math.cos(a), 600 + 760 * math.sin(a)
    x3, y3 = 540 + 760 * math.cos(a + .09), 600 + 760 * math.sin(a + .09)
    body += f'<path d="M540 600 L{x2:.0f} {y2:.0f} L{x3:.0f} {y3:.0f} Z" fill="{GOLD3}" opacity=".055"/>'
body += glass(48, 48, 984, 984, 72)
body += '<circle cx="540" cy="600" r="330" fill="url(#halo)"/>'
# falling clovers, coins and sparkles (abundance)
for x, y, s, r, op in [(150, 380, .55, -20, .9), (930, 330, .5, 25, .85), (220, 760, .42, 40, .8), (880, 720, .6, -35, .9),
                       (330, 330, .32, 10, .55), (770, 320, .36, -15, .6), (110, 600, .3, 30, .5), (975, 560, .3, -10, .5)]:
    body += clover(x, y, s, r, fill="url(#leaf2)", stem=False, op=op)
for x, y, r, rot in [(300, 880, 34, -12), (790, 885, 30, 14), (205, 520, 24, 8), (870, 470, 26, -10), (120, 860, 22, 5), (960, 680, 24, -6)]:
    body += coin(x, y, r, rot)
for x, y, r in [(260, 300, 18), (820, 400, 22), (180, 690, 14), (930, 820, 16), (420, 300, 12), (650, 310, 16), (980, 260, 12), (100, 470, 12)]:
    body += sparkle(x, y, r)
# the mascot, its ping turned gold, holding a big clover
p = penguin(540, 640, 1.25).replace("url(#iceh)", "url(#goldh)").replace('fill="url(#ice)"', 'fill="url(#gold)"')
body += p
body += clover(668, 588, .95, 14)
body += sparkle(770, 470, 26) + sparkle(640, 470, 14)
# words
# title on a dark glass plate, so it reads on any part of the rays
body += f'<rect x="196" y="78" width="688" height="196" rx="98" fill="{GOLD}" opacity=".30" filter="url(#blur30)"/>'
body += f'<rect x="196" y="78" width="688" height="196" rx="98" fill="#021A11" opacity=".74"/>'
body += glass(196, 78, 688, 196, 98)
body += f'<rect x="197.5" y="79.5" width="685" height="193" rx="96.5" fill="none" stroke="url(#goldh)" stroke-opacity=".75" stroke-width="3"/>'
body += f'<text x="540" y="196" font-family="{DISPLAY}" font-size="112" fill="#000" opacity=".35" text-anchor="middle" filter="url(#soft)">برکت خریدت</text>'
body += f'<text x="540" y="190" font-family="{DISPLAY}" font-size="112" fill="url(#goldh)" text-anchor="middle">برکت خریدت</text>'
body += f'<text x="540" y="244" font-family="{BODY}" font-weight="700" font-size="24" fill="#ECFDF5" opacity=".92" text-anchor="middle">یه هدیه از طرف پینگو</text>'
body += clover(214, 176, .5, -18) + clover(866, 176, .5, 18)
body += sparkle(250, 92, 16) + sparkle(838, 262, 14) + sparkle(820, 96, 10)
body += pill(360, 866, 360, 88, "", fill="#FFFFFF", size=34)
body += f'<text x="612" y="923" font-family="{BODY}" font-weight="800" font-size="36" fill="#065F46" text-anchor="middle">حجم هدیه</text>'
body += f'<text x="454" y="924" font-family="{BODY}" font-weight="800" font-size="38" fill="#D97706" text-anchor="middle" direction="ltr">+10%</text>' 
body += f'<text x="540" y="1000" font-family="{BODY}" font-weight="700" font-size="24" fill="{GOLD3}" opacity=".8" letter-spacing="8" text-anchor="middle">PINGO • VPN</text>'

svgt = f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}"><defs>{DEFS}{EXTRA}</defs>{body}</svg>'
os.makedirs(OUT, exist_ok=True)
open(OUT + "/barakat.svg", "w").write(svgt)
subprocess.run(["rsvg-convert", "-w", "1080", "-h", "1080", OUT + "/barakat.svg", "-o", OUT + "/barakat.png"], check=True)
print("ok")
