import os
import smtplib
from email.message import EmailMessage

def send_onboarding_email(to_email: str, plaintext_key: str, tier: str):
    """
    Sends the onboarding email with the plaintext API key.
    Uses stdlib smtplib + email.message.
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("FROM_EMAIL")

    # missing config -> skip (don't crash, just ensure logs show warning)
    if not all([smtp_host, smtp_port, smtp_user, smtp_pass, from_email]):
        print(f"[EMAIL WARNING] Skipping email to {to_email}: Missing SMTP configuration.")
        return

    msg = EmailMessage()
    msg["Subject"] = "Your QubitGrid API Key"
    msg["From"] = from_email
    msg["To"] = to_email

    dashboard_url = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/") + "/dashboard"

    # Plain text content
    msg.set_content(f"""
Welcome to QubitGrid {tier}!

Thank you for subscribing. Here is your API Key.
PLEASE SAVE THIS KEY IMMEDIATELY. We do not store the plaintext version.

API KEY:
{plaintext_key}

You need this key to access your dashboard:
{dashboard_url}

If you lose this key, you can reset it via the dashboard if you still have an active session, 
or you will need to contact support.
""")

    # HTML content
    msg.add_alternative(f"""
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1f2937; line-height: 1.5;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #111827;">Welcome to QubitGrid {tier}!</h2>
            <p>Thank you for subscribing. Here is your new API Key.</p>
            
            <div style="background-color: #f3f4f6; padding: 16px; border-radius: 8px; margin: 24px 0; border: 1px solid #e5e7eb;">
                <p style="margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; color: #6b7280; font-weight: 600;">Your API Key</p>
                <code style="display: block; font-family: monospace; font-size: 16px; color: #0b5bd7; word-break: break-all;">{plaintext_key}</code>
            </div>

            <p><strong>Important:</strong> We do not store this key. Please save it in a password manager immediately.</p>
            
            <p>
                <a href="{dashboard_url}" style="display: inline-block; background-color: #0b5bd7; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-weight: 500;">Go to Dashboard</a>
            </p>
        </div>
    </body>
    </html>
    """, subtype='html')

    try:
        with smtplib.SMTP(smtp_host, int(smtp_port)) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        print(f"[EMAIL] Onboarding email sent to {to_email}")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send to {to_email}: {e}")
