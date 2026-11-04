<div align="center">

# 🚩 THEM?! CTF 2026 — Solutions & Writeups

**Comprehensive bilingual (English / Russian) writeups and exploit writeups for THEM?! CTF 2026.**

[![CTF](https://img.shields.io/badge/CTF-THEM%3F!%202026-e74c3c.svg?style=for-the-badge&logo=target)]()
[![Solved Tasks](https://img.shields.io/badge/tasks%20solved-16%20%2F%2016-2ecc71.svg?style=for-the-badge&logo=checkmarx)]()
[![Languages](https://img.shields.io/badge/writeups-RU%20%7C%20EN-3498db.svg?style=for-the-badge&logo=translate)]()
[![License](https://img.shields.io/badge/license-MIT-f39c12.svg?style=for-the-badge)](LICENSE)

*All writeups feature detailed step-by-step methodology, vulnerability analysis, reproduction scripts, and key lessons learned.*

[📖 Full Writeups Index](./WRITEUPS_INDEX.md) • [👾 Reverse Engineering](#-reverse-engineering--malware-analysis) • [💥 Pwn & Shellcode](#-binary-exploitation--shellcoding) • [🌐 Web & Embedded](#-web--embedded-security) • [🔐 Cryptography](#-cryptography)

---

</div>

## 🎯 Highlights & Technical Scope

This repository documents 16 solved challenges spanning offensive security, binary exploitation, and cryptanalysis:

* **Custom VM Deobfuscation:** Disassembling and reversing a virtualized, packed Lua malware loader in `last_dance`.
* **Rust Native Reverse Engineering:** Dissecting stripped Rust compiled PE binary in `🦀?`.
* **Android Application Security:** Decompiling APK and bypassing client-side validation logic in `Good9`.
* **Embedded & Router Exploitation:** Multi-stage authentication bypass and command injection on simulated firmware in `A Cute Magical Router Gateway` and its `Revenge` counterpart.
* **x86/x64 Shellcoding:** Handcrafted shellcode execution under strict environmental constraints in `Baby Shellcode`.
* **Cryptanalysis:** Attacking custom block structures, hash collisions, and seed leakage across `Cascadino Chain`, `No 7race`, and `Despacito`.

---

## 📂 Challenges by Category

### 👾 Reverse Engineering & Malware Analysis

| Challenge | Highlights | Target / Platform | EN Writeup | RU Writeup |
| :--- | :--- | :--- | :---: | :---: |
| **last_dance** | Virtualized & packed Lua malware loader, custom bytecode VM reversing | Lua VM / Linux | [Read (EN)](./last_dance/writeup_en.md) | [Читать (RU)](./last_dance/writeup_ru.md) |
| **🦀?** | Reverse engineering a compiled, stripped Rust Windows executable (`crabbymonty.exe`) | Rust / Win64 PE | [Read (EN)](./%F0%9F%A6%80%3F/writeup_en.md) | [Читать (RU)](./%F0%9F%A6%80%3F/writeup_ru.md) |
| **Good9** | Android mobile application reversing, bytecode static & dynamic analysis | Android APK | [Read (EN)](./Good9/writeup_en.md) | [Читать (RU)](./Good9/writeup_ru.md) |
| **Entropy Core** | Windows binary unpacker analysis, entropy calculation and secret reconstruction | Win32 PE | [Read (EN)](./Entropy%20Core/writeup_en.md) | [Читать (RU)](./Entropy%20Core/writeup_ru.md) |
| **Eyes Chico** | Reverse engineering `1983.exe` crackme, anti-analysis checks bypass | Win32 PE | [Read (EN)](./Eyes%20Chico/writeup_en.md) | [Читать (RU)](./Eyes%20Chico/writeup_ru.md) |
| **lesgo** | Native binary analysis of input validation logic in ELF checker | Linux ELF | [Read (EN)](./lesgo/writeup_en.md) | [Читать (RU)](./lesgo/writeup_ru.md) |
| **Old Cassette** | Audio stream decoding, signal frequency extraction and binary recovery | Audio / Binary | [Read (EN)](./Old%20Cassette/writeup_en.md) | [Читать (RU)](./Old%20Cassette/writeup_ru.md) |

### 💥 Binary Exploitation & Shellcoding

| Challenge | Highlights | Target / Platform | EN Writeup | RU Writeup |
| :--- | :--- | :--- | :---: | :---: |
| **Baby Shellcode** | Writing custom shellcode to bypass memory restrictions and spawn shell | Linux x86_64 | [Read (EN)](./Baby%20Shellcode/writeup_en.md) | [Читать (RU)](./Baby%20Shellcode/writeup_ru.md) |

### 🌐 Web & Embedded Security

| Challenge | Highlights | Vulnerability | EN Writeup | RU Writeup |
| :--- | :--- | :--- | :---: | :---: |
| **A Cute Magical Router Gateway** | Network router web management interface assessment | Auth Bypass & Logic Flaw | [Read (EN)](./A%20Cute%20Magical%20Router%20Gateway/writeup_en.md) | [Читать (RU)](./A%20Cute%20Magical%20Router%20Gateway/writeup_ru.md) |
| **Revenge Of The Cute Magical Router Gateway** | Hardened router challenge with filtered parameters and state checks | Advanced Route & Header Injection | [Read (EN)](./Revenge%20Of%20The%20Cute%20Magical%20Router%20Gateway/writeup_en.md) | [Читать (RU)](./Revenge%20Of%20The%20Cute%20Magical%20Router%20Gateway/writeup_ru.md) |
| **SEAM** | Complex multi-tier web application with session tampering & privilege escalation | Access Control Flaw (1000 pts) | [Read (EN)](./SEAM/writeup_en.md) | [Читать (RU)](./SEAM/writeup_ru.md) |

### 🔐 Cryptography & Forensics

| Challenge | Highlights | Core Primitive | EN Writeup | RU Writeup |
| :--- | :--- | :--- | :---: | :---: |
| **Cascadino Chain** | Block cipher structure attack and cascade degradation | Block Cipher / Hash Chaining | [Read (EN)](./Cascadino%20Chain/writeup_en.md) | [Читать (RU)](./Cascadino%20Chain/writeup_ru.md) |
| **No 7race** | State recovery and mathematical flaw in pseudo-random generation | PRNG Flaw | [Read (EN)](./No%207race/writeup_en.md) | [Читать (RU)](./No%207race/writeup_ru.md) |
| **Despacito** | Cryptographic algorithm weak key scheduling attack | S-Box / Key Scheduling | [Read (EN)](./Despacito/writeup_en.md) | [Читать (RU)](./Despacito/writeup_ru.md) |
| **Ancient Signals** | Modulated signal recovery and demodulation from telemetry transmission | Signal Analysis / Stego | [Read (EN)](./Ancient%20Signals/writeup_en.md) | [Читать (RU)](./Ancient%20Signals/writeup_ru.md) |
| **phantom** | Container artifact extraction and hidden archive recovery | Forensics / Archive Stego | [Read (EN)](./phantom/writeup_en.md) | [Читать (RU)](./phantom/writeup_ru.md) |

---

## 🛠️ Tooling & Methodology

During the competition, the following toolchains were utilized:
* **Disassembly & Decompilation:** Ghidra, IDA Pro, Binary Ninja, JADX-GUI (Android), unluac / luadec (Lua VM).
* **Exploitation & Scripting:** Python 3 (`pwntools`, `pycryptodome`, `requests`), GDB with GEF/pwndbg.
* **Traffic & Web Analysis:** Burp Suite Professional, Wireshark, CyberChef.

---

## 📜 Repository Structure

```text
THEM-CTF_2026-writeups/
├── WRITEUPS_INDEX.md                           # Quick jump index
├── README.md                                   # Main presentation catalog
├── LICENSE                                     # MIT License
├── A Cute Magical Router Gateway/              # [Web] writeup_en.md, writeup_ru.md
├── Ancient Signals/                            # [Crypto/Signals]
├── Baby Shellcode/                             # [Pwn/Shellcode]
├── Cascadino Chain/                            # [Crypto]
├── Despacito/                                  # [Crypto]
├── Entropy Core/                               # [Reversing]
├── Eyes Chico/                                 # [Reversing]
├── Good9/                                      # [Mobile/Android]
├── No 7race/                                   # [Crypto]
├── Old Cassette/                               # [Reversing/Audio]
├── Revenge Of The Cute Magical Router Gateway/ # [Web/Embedded]
├── SEAM/                                       # [Web/1000pts]
├── last_dance/                                 # [Reversing/Lua VM]
├── lesgo/                                      # [Reversing/ELF]
├── phantom/                                    # [Forensics]
└── 🦀?/                                        # [Reversing/Rust]
```

---

## 📄 License

This collection of writeups is licensed under the [MIT License](LICENSE). Challenge files, binaries, and prompts remain the intellectual property of the THEM?! CTF 2026 organizers.
