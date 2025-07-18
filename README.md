# Image Steganography Project 🚀

A powerful GUI-based image steganography tool with **advanced encryption** and a professional **cyber-security interface**.

![Banner](banner.png)

## Features

1. **LSB Steganography**  
   • Hide text inside images  
   • Hide one image inside another  
2. **DCT Steganography** for JPEGs  
3. **Advanced Encryption Suite**  
   • AES-256 (CBC / GCM)  
   • Fernet (AES-128)  
   • RSA-2048 & Hybrid RSA+AES  
   • PBKDF2 key derivation & secure salts  
4. **Professional Cyber-Security GUI**  
   • Dark theme, neon highlights  
   • Matrix-rain animation, terminal output  
   • Progress bars, LED status indicators  
5. **Cross-Platform** (Windows, macOS, Linux)
6. **No external dependencies beyond PyPI – easily installable**

---

## Quick Start

```bash
# Clone
$ git clone <repo>
$ cd image-steganography

# Install dependencies
$ pip install -r requirements.txt

# Run
$ python steganography_project.py
```

---

## Screenshots

| Hide Text | Extract Image |
|-----------|--------------|
| ![](screenshots/hide_text.png) | ![](screenshots/extract_image.png) |

---

## Project Structure

```text
.
├── steganography_project.py   # Main GUI application
├── steganography_core.py      # Core steg algorithms (LSB, DCT)
├── encryption_module.py       # AES, RSA, hybrid crypto, hashing
├── gui_themes.py              # Cyber-security GUI styling & animations
├── requirements.txt           # Dependencies
└── README.md                  # Documentation
```

---

## Security Notes 🔐

- **Encryption:** All payloads can be encrypted with AES-256 or Hybrid RSA+AES before embedding.  
- **Keys & Passwords:** Keys are derived with PBKDF2 (100k iterations) and random salts.  
- **Integrity:** Optional SHA-256 hashes ensure data integrity after extraction.  
- **Formats:** Use PNG/BMP/TIFF for lossless LSB embedding. For JPEG use DCT mode.

---

## License

MIT © 2025

---

*added by naveen on 15-jun_2025*
