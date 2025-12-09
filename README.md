# 🔐 ResetApp

A lightweight, secure internal web application for Google Workspace administrators (teachers) to reset student passwords within their organizational unit. Built with Flask, Google OAuth2 SSO, and the Admin SDK, it features:

- **Google SSO** for teacher authentication  
- **Directory API** integration with domain‑wide delegation  
- **Single‑page** UX: login, form, and results on one page  
- **Animated confetti** and slick button hover effects  
- **Docker‑ready** and configurable via environment variables  

---

## 📝 Features

- **Single‑Page Interface**  
  - Displays login prompt or password‑reset form depending on auth state  
- **Secure OAuth2 Flow**  
  - Google Sign‑In (SSO) with CSRF‑protected state parameter  
  - `google-auth-oauthlib` + `google-auth` for token handling  
- **Admin SDK Integration**  
  - Service account with domain‑wide delegation  
  - Reset student password, enforce “change at next login”  
  - Organizational‑unit check to restrict scope  
- **Polished UI/UX**  
  - Bootstrap 5 styling and icons  
  - Avatar dropdown showing teacher’s initial and email  
  - Confetti animation via [party.js] on successful reset  
  - Button “pop” effect on hover  

---

## 🚀 Quick Start

### Prerequisites

- Python 3.9+  
- Docker & Docker Compose (optional)  
- A Google Workspace super‑admin account  
- A Google Cloud project with:
  - **OAuth 2.0 Client (Web app)**
  - **Service account** with JSON key & **domain‑wide delegation**  
  - **Admin SDK** (Directory API) enabled  

### Clone & Install

```bash
git clone https://github.com/your-org/reset-app.git
cd reset-app

# Create & activate a virtualenv (optional but recommended)
python -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate

pip install -r requirements.txt
