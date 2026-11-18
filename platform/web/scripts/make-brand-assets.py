"""Generate the Protocol Agent brand mark.

Design: a gradient flat-top hexagon ring enclosing two opposed packet-flow
arrows (traffic exchange). The login page renders logo.png with
`brightness-0 invert`, so the mark is drawn as strokes on a transparent
background to keep its silhouette when inverted to white.

Outputs:
  public/brand-logo.png   1024 transparent mark (login, sidebar)
  public/logo.png         same mark (compatibility with older references)
  public/logo.svg         vector mark
  src/app/icon.png        512 gradient rounded-square app icon with white mark
  src/app/favicon.ico     multi-size favicon
"""
from PIL import Image, ImageDraw

S = 2048
CX = CY = S // 2
R = 760
RING = 120
ARROW = 108
X0, X1 = 650, 1398
Y1, Y2 = 930, 1118
HEAD = 176


def hex_points(cx, cy, r):
    import math
    return [
        (cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a)))
        for a in (0, 60, 120, 180, 240, 300)
    ]


def circle(draw, x, y, r):
    draw.ellipse([x - r, y - r, x + r, y + r], fill=255)


mask = Image.new("L", (S, S), 0)
d = ImageDraw.Draw(mask)

pts = hex_points(CX, CY, R)
d.line(pts + [pts[0]], fill=255, width=RING, joint="curve")
for x, y in pts:
    circle(d, x, y, RING // 2)

# Upper arrow: left -> right
d.line([(X0, Y1), (X1 - HEAD + 8, Y1)], fill=255, width=ARROW)
circle(d, X0, Y1, ARROW // 2)
d.polygon(
    [(X1 - HEAD, Y1 - HEAD // 2), (X1, Y1), (X1 - HEAD, Y1 + HEAD // 2)],
    fill=255,
)

# Lower arrow: right -> left
d.line([(X1, Y2), (X0 + HEAD - 8, Y2)], fill=255, width=ARROW)
circle(d, X1, Y2, ARROW // 2)
d.polygon(
    [(X0 + HEAD, Y2 - HEAD // 2), (X0, Y2), (X0 + HEAD, Y2 + HEAD // 2)],
    fill=255,
)

# Vertical gradient #5B2BD6 -> #A35CFF.
c1, c2 = (91, 43, 214), (163, 92, 255)
grad = Image.new("RGBA", (1, S))
for y in range(S):
    t = y / (S - 1)
    grad.putpixel((0, y), tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3)) + (255,))
grad = grad.resize((S, S), Image.BILINEAR)

mark = Image.new("RGBA", (S, S), (0, 0, 0, 0))
mark.paste(grad, (0, 0), mask)
mark = mark.resize((1024, 1024), Image.LANCZOS)
mark.save("public/brand-logo.png", optimize=True)
mark.save("public/logo.png", optimize=True)

# App icon: gradient rounded square with a white mark.
ICON = 512
bg_mask = Image.new("L", (ICON, ICON), 0)
ImageDraw.Draw(bg_mask).rounded_rectangle([0, 0, ICON - 1, ICON - 1], radius=104, fill=255)
bg = Image.new("RGBA", (ICON, ICON), (0, 0, 0, 0))
bg_grad = grad.resize((ICON, ICON), Image.LANCZOS)
bg.paste(bg_grad, (0, 0), bg_mask)

mark_size = int(ICON * 0.64)
white_mask = mask.resize((mark_size, mark_size), Image.LANCZOS)
white = Image.new("RGBA", (mark_size, mark_size), (255, 255, 255, 0))
white.putalpha(white_mask)
bg.alpha_composite(white, ((ICON - mark_size) // 2, (ICON - mark_size) // 2))
bg.save("src/app/icon.png", optimize=True)

fav = bg.resize((256, 256), Image.LANCZOS)
fav.save("src/app/favicon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128)])

svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" role="img" aria-label="Protocol Agent">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#5b2bd6"/>
      <stop offset="1" stop-color="#a35cff"/>
    </linearGradient>
  </defs>
  <g fill="none" stroke="url(#g)" stroke-width="30" stroke-linecap="round" stroke-linejoin="round">
    <path d="M446 256 351 420.5 161 420.5 66 256 161 91.5 351 91.5Z"/>
  </g>
  <g fill="none" stroke="url(#g)" stroke-width="27" stroke-linecap="round">
    <path d="M163 232.5H330"/>
    <path d="M186 279.5H349"/>
  </g>
  <g fill="url(#g)">
    <path d="M320 211 349 232.5 320 254Z"/>
    <path d="M192 258 163 279.5 192 301Z"/>
  </g>
</svg>
"""
with open("public/logo.svg", "w", encoding="utf-8") as fh:
    fh.write(svg)

print("brand assets written")