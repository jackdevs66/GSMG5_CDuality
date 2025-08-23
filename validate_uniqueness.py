import hashlib
import base64
import binascii
from pathlib import Path
from Crypto.Cipher import AES


EXPECTED_SHA256 = "4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081"


def xor_key(passwords: list[str]) -> str:
    hs = [hashlib.sha256(p.encode("utf-8")).digest() for p in passwords]
    out = bytearray(hs[0])
    for h in hs[1:]:
        for i, b in enumerate(h):
            out[i] ^= b
    return binascii.hexlify(bytes(out)).decode("utf-8")


def try_key(b64_blob: str, hex_key: str) -> bytes | None:
    blob = base64.b64decode(b64_blob)
    if not (blob.startswith(b"Salted__") and len(blob) >= 16):
        return None
    salt = blob[8:16]
    ct = blob[16:]
    pwd = binascii.unhexlify(hex_key)
    key_iv = b""
    prev = b""
    while len(key_iv) < 48:
        prev = hashlib.md5(prev + pwd + salt).digest()
        key_iv += prev
    key = key_iv[:32]
    iv = key_iv[32:48]
    c = AES.new(key, AES.MODE_CBC, iv)
    pt = c.decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        return pt[:-pad]
    return None


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    cosmic_file = repo_root / "cosmic_duality.txt"
    b64 = cosmic_file.read_text(encoding="utf-8").replace("\n", "")

    p1 = "matrixsumlist"
    p2 = "enter"
    p3 = "lastwordsbeforearchichoice"
    p4 = "thispassword"

    p5_cands = [
        "6108766549978798108108736759668",
        "matrixsumlist",
        "sumlist",
        "matrixsums",
        "sumsofmatrix",
        "rowcolsum",
        "rowcolsumlist",
    ]

    p6_cands = [
        "ourfirsthintisyourlastcommand",
        "firsthintisyourlastcommand",
        "firsthintlastcommand",
        "yourlastcommand",
        "lastcommand",
    ]

    p7_cands = [
        "answertoo",
        "answertwo",
        "answer2",
        "shabefanstoo",
        "secondanswer",
        "answeralso",
    ]

    successes: list[tuple[list[str], str, str]] = []
    count = 0
    for p5 in p5_cands:
        for p6 in p6_cands:
            for p7 in p7_cands:
                count += 1
                pwds = [p1, p2, p3, p4, p5, p6, p7]
                key = xor_key(pwds)
                pt = try_key(b64, key)
                if pt is not None:
                    h = hashlib.sha256(pt).hexdigest()
                    print("SUCCESS", pwds, "Key=", key, "SHA256=", h)
                    successes.append((pwds, key, h))

    print("Tried", count, "combinations; Successes=", len(successes))
    assert len(successes) == 1 and successes[0][2].lower() == EXPECTED_SHA256.lower(), (
        "Not unique or unexpected hash"
    )
    print("UNIQUE and HASH OK")


if __name__ == "__main__":
    main()


