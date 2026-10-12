"""Build bgshare.ico (multi-size) and bgshare.png (tray) from the Blue Giraffe logo embedded in bgshare_peer.py."""
import base64, io, os, re
from PIL import Image, ImageDraw
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "bgshare_peer.py"), encoding="utf-8") as fh:
    src = fh.read()
logo = Image.open(io.BytesIO(base64.b64decode(re.search(r'LOGO_PNG_B64 = "([^"]+)"', src).group(1)))).convert("RGBA")
# the official logo is wide (BG mark above the wordmark); keep the BG mark (top ~62%) for a square icon
w, h = logo.size
mark = logo.crop((0, 0, w, int(h * 0.62)))
bb = mark.getchannel("A").point(lambda a: 255 if a > 40 else 0).getbbox(); mark = mark.crop(bb)
S = 256; pad = 22
canvas = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ImageDraw.Draw(canvas).rounded_rectangle((0, 0, S - 1, S - 1), radius=56, fill=(255, 255, 255, 255))
mark.thumbnail((S - 2 * pad, S - 2 * pad), Image.LANCZOS)
canvas.alpha_composite(mark, ((S - mark.width) // 2, (S - mark.height) // 2))
canvas.save(os.path.join(here, "bgshare.png"))
canvas.save(os.path.join(here, "bgshare.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("wrote bgshare.ico and bgshare.png")
