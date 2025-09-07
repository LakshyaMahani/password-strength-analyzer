# 🔐 Password Strength Analyzer with Custom Wordlist Generator

A GUI-based **Password Strength Analyzer** and **Custom Wordlist Generator** built with **Python + Tkinter**.

This tool evaluates password strength (using [zxcvbn](https://github.com/dropbox/zxcvbn) if available, otherwise an entropy-based fallback) and generates custom wordlists from user-provided hints (names, pets, dates, etc.). The wordlists include leetspeak variants, year suffixes, and common patterns — useful for demonstrating password cracking risks in a controlled, **ethical** environment.

---

## ✨ Features
- GUI built with **Tkinter**
- Password strength scoring with entropy feedback
- Human-readable suggestions (longer length, use of digits/symbols, etc.)
- Wordlist generation from hints:
  - Case variations (lower/upper/title)
  - Leetspeak substitutions (a→4, e→3, s→$, etc.)
  - Pairwise concatenations
  - Years appended/prepended
  - Common suffixes (123, !, 2020)
- Export generated wordlists as `.txt`
- Preview wordlist inside the GUI

---

## 🛠 Installation

### Prerequisites
- Python 3.8+
- Tkinter (pre-installed with Python on most systems)

### Clone the repo
```bash
git clone https://github.com/LakshyaMahani/password-strength-analyzer.git
cd password-strength-analyzer
