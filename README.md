<div align="center">

# permafrost

x64 PE crypter using block permutation. No encryption, no VirtualProtect — pure math.

---

## Concept

Most crypters XOR/AES code then call VirtualProtect(RWX) to decrypt at runtime. EDRs detect this.

permafrost shuffles .text blocks with Fisher-Yates. Code stays executable, just wrong order.
Stub unshuffles via LCG inverse. ~200 bytes, zero API calls.

Got lazy to develop this further. Need something custom? DM me on Telegram: [Otvratitelnyy](https://t.me/dalbaebIna_o)

---

## Why

First public crypter using block permutation instead of encryption.

---

## Comparison

| | Traditional Crypter | permafrost |
|---|:---:|:---:|
| VirtualProtect call | yes | no |
| RWX memory | runtime API | static PE flag |
| Crypto API | yes | no |
| New sections | often | no |
| Entropy | ~7.5 (random) | unchanged |
| Method | encrypt code | shuffle blocks |

---

## Usage
```bash
pip install pefile
python crypter.py target.exe -o out.exe -b 16
```

`-b` block size　　`-s` seed (optional)

---

## Limitations

x64 only

---

## Credit

If you use permafrost — credit required.

---

## Author

**drinr1** — [github.com/drinr1](https://github.com/drinr1)

---

## License

BSD-3-Clause

</div>
