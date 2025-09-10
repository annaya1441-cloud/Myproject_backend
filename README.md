# Authenticity Validator for Academia — SIH Prototype

A simple Flask app that verifies academic certificates using:
- OCR (pytesseract) for text extraction from uploaded images
- Database match (SQLite) against sample records
- Hash integrity (simulated blockchain) using SHA-256

## Quick Start

1) Create & activate a virtual environment (recommended)

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
```

2) Install dependencies

```bash
pip install -r requirements.txt
```

> Optional: install Tesseract engine if OCR is blank.
- Windows: https://github.com/UB-Mannheim/tesseract/wiki
- macOS: `brew install tesseract`
- Ubuntu/Debian: `sudo apt-get install tesseract-ocr`

3) Run the app

```bash
python app.py
```

Open http://127.0.0.1:5000

## Demo Data

Try this valid certificate:
- Name: **Anika Sharma**
- Roll: **CSE19001**
- Course: **B.Tech CSE**
- Cert ID: **JH-2023-0001**

Also seeded:
- JH-2022-0042 (Rahul Verma, B.Tech EEE)
- JH-2021-0199 (Priya Singh, Diploma Civil)

## Admin

- Login: `/admin/login`
- Credentials: `admin / admin123`

You can view verification logs and manage the blacklist.
