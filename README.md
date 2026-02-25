# LyaphiCrypt

![C++](https://img.shields.io/badge/C++-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)

A custom symmetric encryption algorithm built from scratch, combining mathematical and cryptographic concepts into a cohesive cipher.

---

## 🔐 How It Works

LyaphiCrypt generates a unique keystream for every encryption using three layered techniques:

- **Chaos Theory** — A chaotic sequence seeded from the key ensures the keystream is highly sensitive to any change in input
- **Lagrange Interpolation** — Polynomial evaluation adds mathematical non-linearity to the key derivation process
- **SHA-256** — Used for secure key stretching and HMAC-based integrity verification

Each message is encrypted using a key-derived substitution layer and byte-level diffusion, then authenticated with HMAC-SHA256 to detect tampering or wrong-key attempts.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Encryption Engine | C++ (compiled binary) |
| API Server | Python (Flask) |
| Frontend | HTML, CSS, JavaScript |

---

## 📁 Project Structure

```
LyaphiCrypt/
├── cipher.cpp        # Core encryption/decryption engine
├── cipher.exe        # Compiled Windows binary
├── server.py         # Flask REST API
└── frontend/
    ├── index.html    # Web interface
    ├── style.css     # Styling
    └── app.js        # Frontend logic
```

---

## 🚀 Running Locally

### 1. Compile the C++ engine
```bash
g++ -O2 -std=c++17 -o cipher.exe cipher.cpp
```

### 2. Install Python dependencies
```bash
pip install flask flask-cors
```

### 3. Start the server
```bash
python server.py
```

### 4. Open the frontend
Open `frontend/index.html` in your browser.

> The server runs on `http://127.0.0.1:5000` by default.

---

## ✨ Features

- 🔑 Key-derived S-Box (unique substitution table per key)
- 🔗 Byte-level diffusion (each encrypted byte depends on the previous)
- 🛡️ HMAC-SHA256 authentication (detects wrong keys and tampering)
- ⏱️ Time-based IV (same message + same key → different ciphertext every time)
- 📏 Supports up to **10,000 characters** per message
- 🖥️ Clean web UI with live character counter

---

## 📋 Requirements

- `g++` with C++17 support (MinGW on Windows, GCC on Linux)
- Python 3.8+
- Flask, Flask-CORS

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
