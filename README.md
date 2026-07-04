<!--
30 78 73 6F 6C 6F
-->

# 🛡️ Web Vulnerability Scanner

A lightweight **Python-based Web Vulnerability Scanner** with an interactive **Flask web interface** designed to automate the detection of common web application security vulnerabilities.

The scanner currently performs automated testing for:

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Command Injection
- Basic Server Configuration Issues (HTTP/HTTPS)

The project was built to strengthen practical offensive security skills, automate repetitive security testing tasks, and demonstrate Python-based security tool development.

---

## ✨ Features

- 🌐 Interactive Flask Web Dashboard
- 🔍 SQL Injection Detection
- 💥 Cross-Site Scripting (XSS) Detection
- ⚡ Command Injection Detection
- 🔒 HTTPS Configuration Check
- 📄 Scan Result Reporting
- 🐍 Modular Python Architecture
- 🚀 Easy to Extend with New Vulnerability Modules

---

## 🛠️ Technologies Used

- Python
- Flask
- Requests
- BeautifulSoup4
- HTML Parsing
- Regular Expressions

---

## 📂 Project Structure

```
vulnscanner/
├── app.py
├── scanner.py
├── sql_scanner.py
├── xss_scanner.py
├── templates/
├── static/
└── requirements.txt
```

---

## 🎯 Learning Objectives

This project demonstrates practical knowledge of:

- Web Application Security
- OWASP Top 10 Concepts
- Offensive Security Automation
- HTTP Request/Response Analysis
- Secure Coding Practices
- Python Security Tool Development

---

## ⚠️ Disclaimer

This tool is intended **solely for educational purposes and authorized security assessments**. Always obtain explicit permission before testing any system you do not own.# 🛡️ Web Vulnerability Scanner

A lightweight **Python-based Web Vulnerability Scanner** with a **Flask web interface** for automating basic web application security assessments.

The scanner identifies common web vulnerabilities including **SQL Injection (SQLi)**, **Cross-Site Scripting (XSS)**, **Command Injection**, and basic **HTTP/HTTPS security misconfigurations**. The project was developed to strengthen practical skills in offensive security, web application testing, and Python security automation.

---

## 🚀 Features

- 🌐 Flask Web Interface
- 🔍 SQL Injection Detection
- 💥 Cross-Site Scripting (XSS) Detection
- ⚡ Command Injection Detection
- 🔒 HTTPS Configuration Check
- 📄 Scan Result Dashboard
- 🐍 Modular Python Architecture
- 🔧 Easily Extendable Scanner Modules

---

## 🖥️ Preview

> Add screenshots of the homepage and scan results here.

| Home | Results |
|------|---------|
| Screenshot | Screenshot |

---

## 📁 Project Structure

```
.
├── app.py
├── scan.py
├── sql_scanner.py
├── xss_scanner.py
├── cmd_scanner.py
├── requirements.txt
├── Pipfile
├── templates
│   ├── index.html
│   └── result.html
└── README.md
```

---

## 🏗️ Technologies Used

- Python 3
- Flask
- Requests
- BeautifulSoup4
- HTML
- CSS

---

## 🔍 Vulnerability Checks

| Vulnerability | Status |
|--------------|--------|
| SQL Injection (SQLi) | ✅ |
| Cross-Site Scripting (XSS) | ✅ |
| Command Injection | ✅ |
| HTTPS Configuration | ✅ |

---

## ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/0xS0l0/vulnscanner.git
cd vulnscanner
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python app.py
```

Open your browser

```
http://127.0.0.1:5000
```

---

## 📚 Learning Objectives

This project demonstrates practical knowledge of:

- Web Application Security
- OWASP Top 10
- Security Automation
- Python Development
- Flask Web Applications
- HTTP Request & Response Analysis
- Offensive Security Concepts

---

## 🚧 Future Improvements

- Authentication Testing
- CSRF Detection
- Security Header Analysis
- Directory Enumeration
- Cookie Security Checks
- Open Redirect Detection
- SSRF Detection
- File Upload Testing
- Multi-threaded Scanning
- Export Reports (HTML/PDF/JSON)
- Scan History
- API Security Testing

---

## ⚠️ Disclaimer

This project is intended **for educational purposes and authorized security testing only**.

Only scan systems that you own or have explicit permission to test.

Unauthorized security testing may violate applicable laws and regulations.

---

## 👨‍💻 Author

**Dhanesh C (0xS0l0)**

- GitHub: https://github.com/0xS0l0
- LinkedIn: https://linkedin.com/in/cdhanesh

---

⭐ If you found this project useful, consider giving it a star!
