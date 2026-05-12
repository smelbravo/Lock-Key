# 🔐 Lock & Key

> Modern Password Manager Ecosystem for Web & Firefox

Lock & Key is a secure and modern password manager designed to provide encrypted credential storage, secure notes, and seamless Firefox browser integration through a lightweight extension.

The platform combines:
- 🌐 A complete web dashboard
- 🦊 A Firefox extension with autofill support
- 🔒 Strong encryption & secure authentication
- ⚡ Modern responsive UI inspired by premium password managers

---

# ✨ Features

## 🌍 Web Application
- User registration & login
- Secure password vault
- Encrypted secure notes
- Password generator
- Password strength checker
- Vault search system
- Category & tag organization
- Dark / Light mode
- Responsive dashboard
- Profile & settings management
- Change master password
- Export / Import encrypted vault

---

## 🦊 Firefox Extension
- Quick vault access
- Autofill login forms
- Detect login pages
- Save new credentials popup
- Search saved entries
- Copy credentials instantly
- Vault synchronization with website
- Secure session authentication

---

# 🔐 Security Features

Lock & Key was designed with security as a priority.

### Implemented Security
- AES-256 encryption
- Password hashing using `password_hash()`
- Secure PHP sessions
- CSRF protection
- PDO prepared statements
- XSS protection
- Input validation
- Secure authentication tokens
- Auto logout after inactivity
- Encrypted secure notes
- Secure REST API communication

⚠️ Sensitive vault data is never stored in plain text.

---

# 🛠️ Tech Stack

## Backend
- PHP 8+
- MySQL
- REST API

## Frontend
- HTML5
- CSS3
- JavaScript

## Extension
- Firefox WebExtension API

---

# 📁 Project Structure

```bash
Lock-And-Key/
│
├── backend/
├── frontend/
├── api/
├── extension/
├── database/
├── config/
├── assets/
└── README.md
```

---

# 🚀 Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/smelbravo/Lock-Key.git
```

---

## 2️⃣ Install XAMPP / WAMP

Recommended:
- XAMPP
- PHP 8+
- MySQL

---

## 3️⃣ Move Project

Move the project folder to:

### XAMPP
```bash
htdocs/
```

### Example
```bash
C:/xampp/htdocs/lock-and-key
```

---

## 4️⃣ Create Database

Open:
```bash
http://localhost/phpmyadmin
```

Create database:
```sql
lockandkey
```

Import:
```bash
/database/schema.sql
```

---

## 5️⃣ Configure Database

Edit:

```bash
/config/database.php
```

Example:

```php
$host = "localhost";
$dbname = "lockandkey";
$user = "root";
$password = "";
```

---

## 6️⃣ Run Website

Start:
- Apache
- MySQL

Open:

```bash
http://localhost/lock-and-key
```

---

# 🦊 Firefox Extension Setup

## Temporary Installation

Open Firefox and go to:

```bash
about:debugging
```

Then:
1. Click **This Firefox**
2. Click **Load Temporary Add-on**
3. Select:

```bash
extension/manifest.json
```

---

# 🧪 Testing Autofill

1. Login into Lock & Key extension
2. Open a login website
3. Autofill suggestions should appear
4. Save credentials popup should trigger after login

---

# 📡 API

The platform includes a REST API for:
- Authentication
- Vault management
- Notes management
- Extension communication

Responses use JSON format.

---

# 🎨 UI Design

Inspired by:
- Dashlane
- Norton Password Manager
- Bitwarden
- 1Password

Design goals:
- Modern
- Minimal
- Cybersecurity aesthetic
- Fast & responsive

---

# 🔒 Encryption

Sensitive data is encrypted before being stored in the database.

Examples:
- Passwords
- Notes
- URLs
- Emails
- Usernames

Encryption uses:
- AES-256
- Secure session handling
- Backend decryption only for authenticated users

---

# ⚠️ Disclaimer

This project is for educational and development purposes.

Before production deployment:
- Perform security audits
- Configure HTTPS
- Use secure hosting
- Harden server configuration

---

# 📌 Roadmap

- [ ] Two-Factor Authentication (2FA)
- [ ] Biometric unlock
- [ ] Password breach checker
- [ ] Mobile app
- [ ] Cloud sync improvements
- [ ] Secure sharing system
- [ ] Offline encrypted vault mode

---

# 🤝 Contributing

Contributions are welcome.

Feel free to:
- Fork the project
- Open issues
- Submit pull requests

---

# 📄 License

MIT License

---

# 👨‍💻 Author

Developed by **Your Name**

---

# ⭐ Support

If you like the project:
- Leave a star ⭐
- Share feedback
- Contribute improvements
