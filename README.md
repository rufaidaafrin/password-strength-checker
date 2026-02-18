# 🔐 Password Strength Checker

A full-stack password security analysis web app built with FastAPI and a modern HTML/CSS/JS frontend.

## ✨ Features
- Entropy-based strength scoring  
- Leaked password detection (Have I Been Pwned API)  
- Password policy enforcement  
- Rate-limited API to mitigate brute-force abuse  
- Real-time visual strength meter  
- Show/Hide password toggle  

## 🧰 Tech Stack
- Backend: Python, FastAPI  
- Frontend: HTML, CSS, JavaScript  
- Security: SlowAPI (rate limiting)  
- External API: Have I Been Pwned (k-anonymity)  

## ▶️ Run Locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
