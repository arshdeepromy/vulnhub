#!/usr/bin/env python3
"""Base64 a screenshot small enough to travel back over the tool channel.

  python3 dev/shipshot.py dev/shots/dashboard--phone.png [max_kb] [max_px]
"""
import base64, io, sys
from PIL import Image

src = sys.argv[1]
max_kb = int(sys.argv[2]) if len(sys.argv) > 2 else 70
max_px = int(sys.argv[3]) if len(sys.argv) > 3 else 1400

im = Image.open(src).convert('RGB')
w, h = im.size
if h > max_px:
    im = im.crop((0, 0, w, max_px))
scale = 1.0
for q in (72, 60, 48, 38, 30):
    for s in (1.0, 0.8, 0.65, 0.5):
        t = im.resize((max(1, int(im.width * s)), max(1, int(im.height * s)))) if s < 1 else im
        buf = io.BytesIO()
        t.save(buf, 'JPEG', quality=q, optimize=True)
        if buf.tell() <= max_kb * 1024:
            sys.stderr.write(f"{src} {im.width}x{im.height} -> {t.width}x{t.height} q{q} {buf.tell()//1024}KB\n")
            print(base64.b64encode(buf.getvalue()).decode())
            sys.exit(0)
sys.stderr.write("could not get under the size cap\n")
sys.exit(1)
