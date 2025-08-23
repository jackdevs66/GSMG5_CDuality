## GSMG Duality — Reproducible solution (SalPhaseIon + Cosmic Duality)

### A note before we begin
To everyone still exploring this puzzle: I wish you clarity, patience, and a bit of luck. If what you find here becomes the key that finally unlocks your path, consider supporting this effort. With your help I’ll keep publishing new notes and hints that make the path clearer for others.

Donations (thank you):
- BTC: `16jynNBMGeQSSNiAjJABfpCd98L5vncbj7`
- ETH, BNB, USDT, USDC: `0x61200Ac01e8B635e4C3FecBEd73DbAb898Cae0a9` (BEP20, ERC20)
- Solana: `2SwRex7tvqY2jVJM39TnPb6DmnM61ZGwxZvQetEqsGhR`

---

This folder contains minimal scripts and instructions to reproduce the final stage of the GSMG.io puzzle using:
- `SalPhaseIon.txt` → 7 textual parts
- `cosmic_duality.txt` → OpenSSL `Salted__` AES‑256‑CBC blob

### Phase: SalPhaseIon (how the 7 passwords were derived)
1) Identify AB blocks → ASCII (p1, p2)
   - Observation: two long sequences composed only of `a` and `b`, space-separated.
   - Method: map `a→0`, `b→1`, group 8 bits per byte, decode as ASCII.
   - Results: p1=`matrixsumlist`, p2=`enter`.

2) Decode `z`-separated segments with a restricted alphabet (p3, p4)
   - Observation: segments around the letter `z` contain tokens only from `a..i` plus `o`.
   - Hypothesis: map `a..i→1..9`, `o→0`; interpret the resulting decimal string; convert to hex; then to ASCII.
   - Results: p3=`lastwordsbeforearchichoice`, p4=`thispassword`.

3) Resolve inline phrase for p6
   - Literal in text: “our first hint is your last command”.
   - Take the directive literally and compress spacing/case consistently across the puzzle.
   - Result: p6=`yourlastcommand`.

4) Interpret “shabefanstoo” for p7
   - Pattern: `sha` appears across the puzzle as a nudge towards SHA‑256; `ans too` reads naturally as “answer too”.
   - Semantic resolution: a second answer.
   - Result: p7=`secondanswer` (alternatives like `answertoo`, `answertwo`, `answer2`, `answeralso` were tested and rejected).

5) Determine p5 by constrained search + validation
   - p5 is textually ambiguous; use a compact, reasonable candidate set tied to p1’s theme (e.g., `matrixsumlist`, `sumlist`, `rowcolsum`, ...).
   - Criterion: only one candidate, combined with p1–p4,p6,p7, yields valid PKCS#7 padding on the final decryption and the expected output hash.
   - Result: p5=`matrixsumlist`.

### Phase: Cosmic Duality (why OpenSSL, why AES‑256‑CBC)
- Input properties
  - File is base64 (valid charset, length multiple of 4).
  - Base64-decoding reveals the header bytes `53 61 6c 74 65 64 5f 5f` → ASCII `Salted__`.
- OpenSSL convention
  - `Salted__` + 8 bytes of salt is the standard envelope used by `openssl enc`.
  - Key and IV are derived via MD5 `EVP_BytesToKey(password, salt)`.
- Mode and key size selection
  - Prior phases reference `enc -aes-256-cbc -a` explicitly.
  - The password we produce (XOR of seven SHA‑256 digests) is 32 bytes, matching AES‑256.
  - Decryption with AES‑256‑CBC yields correct PKCS#7 padding and a stable binary. Other modes/sizes do not validate.

### Summary of the method
- Compute SHA‑256 for each password, XOR the 7 digests (in order) to obtain a 32‑byte hex key.
- Use that hex as the OpenSSL password (EVP_BytesToKey, MD5) to derive AES‑256 key + IV and decrypt `cosmic_duality.txt`.
- A correct key yields valid PKCS#7 padding and a fixed output hash.

### Passwords (order is critical)
1) `matrixsumlist`
2) `enter`
3) `lastwordsbeforearchichoice`
4) `thispassword`
5) `matrixsumlist`
6) `yourlastcommand`
7) `secondanswer`

### Derived key (hex)
```
a795de117e472590e572dc193130c763e3fb555ee5db9d34494e156152e50735
```

### Expected output
```
SHA-256(cosmic_decrypted.bin) = 4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081
```

### Requirements
- Python 3.8+
- `pip install pycryptodome`
- Place `SalPhaseIon.txt` and `cosmic_duality.txt` one directory above `GSMG_Duality/`.

### Usage
1) Derive key and decrypt:
```powershell
python .\GSMG_Duality\solver_salphasion_cosmic.py
```
Outputs:
- Prints the 7 passwords and the derived hex key
- Writes `cosmic_decrypted.bin` at the project root
- Prints the SHA‑256 of the output

2) Verify the hash:
```powershell
Get-FileHash -Algorithm SHA256 .\cosmic_decrypted.bin
# or
certutil -hashfile .\cosmic_decrypted.bin SHA256
```
Expected:
```
4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081
```

3) Optional: validate uniqueness for parts 5–7
```powershell
python .\GSMG_Duality\validate_uniqueness.py
```
Confirms that, with parts 1–4 fixed and a compact search set for 5–7, exactly one combination yields valid padding and the expected hash.
