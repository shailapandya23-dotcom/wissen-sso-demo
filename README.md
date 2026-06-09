# Wissen Technology SSO Demo

[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://shailapandya.pythonanywhere.com)

Single Flask app with SSO Provider + Client Portal merged into one deployable unit.

**Live demo:** https://shailapandya.pythonanywhere.com

## Run Locally

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:8080

## Deploy on PythonAnywhere (free, no credit card)

1. Create an account at https://www.pythonanywhere.com
2. Open a **Bash console** and clone/upload this repo
3. Create a **Web app** via the dashboard:
   - Manual configuration → Python 3.11 → Flask
4. In the **Web** tab, set:
   - **Source code**: `/home/YOUR_USERNAME/wissen-sso-demo-2`
   - **Working directory**: `/home/YOUR_USERNAME/wissen-sso-demo-2`
   - **WSGI file**: edit it to:
     ```python
     import sys
     sys.path.insert(0, '/home/YOUR_USERNAME/wissen-sso-demo-2')
     from app import app as application
     ```
5. In the **Web** tab → **Environment variables**, add:
   | Variable | Value |
   |---|---|
    | `BASE_URL` | `https://shailapandya.pythonanywhere.com` |
    | `FLASK_SECRET_KEY` | `pick-a-random-secret` |
    | `FLASK_PORT` | `8080` |
    | `REDIRECT_URIS` | `["https://shailapandya.pythonanywhere.com/callback"]` |
6. **Reload** the web app.

## Default Employees

| Name | Email | Password |
|---|---|---|
| Shaila Pandya | shaila.pandya@wissen.com | shaila123 |
| Rahul Pandey | rahul.pandey@wissen.com | rahul456 |
| Nandini Sharma | nandini.sharma@wissen.com | nandini000 |
| Krishna Kaushik | krishna.kaushik@wissen.com | krishna444 |
| Aadya Billore | aadya.billore@wissen.com | aadya888 |

Only `@wissen.com` email addresses are allowed.
