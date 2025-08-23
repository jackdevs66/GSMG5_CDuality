import hashlib
import base64
import binascii
from pathlib import Path
from Crypto.Cipher import AES


def derive_key_from_passwords(passwords: list[str]) -> str:
    """Byte-wise XOR of the 7 SHA-256 digests (in order). Returns lowercase hex."""
    if len(passwords) != 7:
        raise ValueError("Exactly 7 passwords are required")
    hashes = [hashlib.sha256(p.encode("utf-8")).digest() for p in passwords]
    out = bytearray(hashes[0])
    for h in hashes[1:]:
        for i, b in enumerate(h):
            out[i] ^= b
    return binascii.hexlify(bytes(out)).decode("utf-8")


def openssl_decrypt_salted_aes256cbc(b64_blob: str, hex_key: str) -> bytes:
    """Decrypt an OpenSSL `Salted__` base64 blob using AES-256-CBC.

    - Applies EVP_BytesToKey (MD5) KDF to derive key (32) + iv (16) from the password bytes (hex).
    - Validates PKCS#7 padding.
    """
    blob = base64.b64decode(b64_blob)
    assert blob.startswith(b"Salted__") and len(blob) >= 16, "Invalid OpenSSL blob"
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

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    pad = pt[-1]
    if not (1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad):
        raise ValueError("Invalid PKCS#7 padding")
    return pt[:-pad]


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    cosmic_file = repo_root / "cosmic_duality.txt"
    out_file = repo_root / "cosmic_decrypted.bin"

    # Verified passwords (1..7)
    p1 = "matrixsumlist"
    p2 = "enter"
    p3 = "lastwordsbeforearchichoice"
    p4 = "thispassword"
    p5 = "matrixsumlist"
    p6 = "yourlastcommand"
    p7 = "secondanswer"
    pwds = [p1, p2, p3, p4, p5, p6, p7]

    print("Passwords (1..7):")
    for i, p in enumerate(pwds, 1):
        print(f"{i}. {p}")

    key_hex = derive_key_from_passwords(pwds)
    print("Derived key:", key_hex)

    b64 = cosmic_file.read_text(encoding="utf-8").replace("\n", "")
    pt = openssl_decrypt_salted_aes256cbc(b64, key_hex)
    out_file.write_bytes(pt)

    sha = hashlib.sha256(pt).hexdigest()
    print("OK ->", out_file)
    print("SHA-256(cosmic_decrypted.bin) =", sha)


if __name__ == "__main__":
    main()


