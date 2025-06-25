# Secure File Sharing System

A simple and secure file sharing system built with **Flask** (backend) and **Tkinter** (desktop GUI frontend) supporting user authentication, email verification, file upload/download, and access control based on user roles.

---

## Features

- User Signup/Login with password hashing (bcrypt)
- Email verification via Gmail SMTP
- Role-based access:
  - **Ops** can upload files
  - **Client** can download/view files
- File storage and download link generation
- Token-based authentication using JWT
- Encrypted download tokens
- Tkinter GUI for user interaction

---

## Project Structure

```
project/
├── app.py         # Flask backend with REST API
├── gui.py         # Tkinter desktop GUI
├── uploads/       # Uploaded files stored here
└── users.db       # SQLite DB for user and file metadata (auto-generated)
```

---

## How to Run

### 1. Backend (Flask API)

#### Install dependencies:
```bash
pip install flask flask_sqlalchemy flask_mail flask_bcrypt flask_jwt_extended itsdangerous
```

#### Start the server:
```bash
python app.py
```

The API will run at `http://localhost:5000`.

### 2. GUI (Tkinter Client)

#### Run GUI:
```bash
python gui.py
```

---

## User Roles

- **Ops**:
  - Can upload files
  - Can view list of all uploaded files
- **Client**:
  - Can only download files using encrypted download links

---

## API Endpoints

- `POST /api/signup`: Register with email, password, role
- `GET /api/verify_email/<token>`: Email verification
- `POST /api/login`: Get JWT token
- `POST /api/logout`: Logout (JWT cookie unset)
- `POST /api/upload`: Upload file (Only Ops)
- `GET /api/files`: List all uploaded files
- `GET /api/download/<token>`: Download file (JWT required)

---

## Email Setup

- Uses Gmail SMTP (`smtp.gmail.com:587`)
- Configure `MAIL_USERNAME` and `MAIL_PASSWORD` in `app.config`
- Enable "App Passwords" on your Gmail account and use that instead of regular password

---

## Notes

- Supported file types: `.txt`, `.pptx`, `.docx`, `.xlsx`
- Passwords are hashed using Bcrypt before storing
- File downloads require valid JWT and encrypted download token

---


## Author

Developed by **Dronamraju Rajasekhar**  
Email: [dronamrajurajasekhar318@gmail.com](mailto:dronamrajurajasekhar318@gmail.com)

---
