<div align="center">

# permafrost
NO API

x64 PE crypter using block permutation. No encryption, no VirtualProtect — pure math.

---

## Disclaimer

This project is for **educational and research purposes only**. Built to demonstrate block permutation as an alternative to traditional encryption-based PE crypters. Not intended for malicious use.

---

## Concept

Most crypters XOR/AES code then call VirtualProtect(RWX) to decrypt at runtime. EDRs detect this.

permafrost shuffles .text blocks with Fisher-Yates. Code stays executable, just wrong order.
Stub unshuffles via LCG inverse. ~200 bytes, zero API calls.

This project is not actively maintained.

---

## Why

First public crypter using block permutation instead of encryption.

---

## Comparison

| | Traditional Crypter | permafrost |
|---|:---:|:---:|
| VirtualProtect call | yes | no |
| RWX memory | runtime API | static PE flag |
| Win api | Yes | no |
| Entropy | ~7.5 (random) | unchanged |
| Method | encrypt code | shuffle blocks |

---

## Usage

<pre>
pip install pefile
python crypter.py target.exe -o out.exe -b 16
</pre>

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

