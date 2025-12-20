import os
import smtplib
from email.message import EmailMessage

def send_onboarding_email(to_email: str, plaintext_key: str, tier: str):
    """
    Sends the onboarding email with the plaintext API key.
    - ENV=DEV: Sends to DEV_EMAIL_TO (Raises error if missing)
    - ENV=PROD: Sends to actual recipient
    Uses Zoho SMTP via TLS.
    """
    env = os.getenv("ENV", "DEV").upper()
    
    # Configuration
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    
    from_email = os.getenv("SUPPORT_EMAIL_FROM", "support@qubitgrid.ai")
    
    # URL construction
    base_url = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")
    dashboard_url = f"{base_url}/dashboard"
    quickstart_url = "https://qubitgrid.ai/quickstart"
    docs_url = "https://qubitgrid.ai/docs"
    
    # Dev routing logic
    actual_recipient = to_email
    if env == "DEV":
        dev_mode = os.getenv("DEV_EMAIL_MODE", "send")
        dev_to = os.getenv("DEV_EMAIL_TO")
        
        # Strict DEV requirement
        if not dev_to:
            raise ValueError("ENV=DEV but DEV_EMAIL_TO is missing. Cannot send email.")
            
        if dev_mode != "send":
            print(f"[EMAIL DEV] Skipping email to {to_email} (DEV_EMAIL_MODE={dev_mode})")
            return

        print(f"[EMAIL DEV] Rerouting {to_email} -> {dev_to}")
        actual_recipient = dev_to

    # Missing config check
    if not all([smtp_host, smtp_user, smtp_pass]):
        raise ValueError("Missing SMTP configuration (HOST/USER/PASS)")

    # Build Message
    msg = EmailMessage()
    msg["Subject"] = "Your QubitGrid API Key (Phase 1: Prompt Injection Scanner)"
    msg["From"] = from_email
    msg["To"] = actual_recipient
    
    disclaimer = "QubitGrid provides pre-audit readiness tooling only. It does not provide certified audits or compliance attestations."

    # Plaintext content (Full requirement)
    text_body = f"""
Welcome to QubitGrid {tier}!

Thank you for subscribing. Here is your API Key.
PLEASE SAVE THIS KEY IMMEDIATELY. We do not store the plaintext version.

API KEY:
{plaintext_key}

You need this key to access your dashboard:
{dashboard_url}

Quickstart Guide: {quickstart_url}
Developer Docs: {docs_url}

If you lose this key, you can reset it via the dashboard if you still have an active session, 
or you will need to contact support via {from_email}.

---
{disclaimer}
Questions? Reply to this email or contact {from_email}.
"""

    # HTML Body
    html_body = f"""
    <html>
    <body style="font-family: sans-serif; color: #1f2937; line-height: 1.5; background: #f9fafb; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #ffffff; padding: 24px; border-radius: 8px; border: 1px solid #e5e7eb;">
            <h2 style="color: #111827; margin-top: 0;">Welcome to QubitGrid {tier}!</h2>
            <p>Thank you for subscribing.</p>
            
            <div style="background-color: #f3f4f6; padding: 16px; border-radius: 6px; margin: 20px 0; border: 1px solid #e5e7eb;">
                <p style="margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; color: #6b7280; font-weight: 700;">Your API Key</p>
                <code style="display: block; font-family: monospace; font-size: 18px; color: #0b5bd7; word-break: break-all;">{plaintext_key}</code>
            </div>
            
            <p style="font-size: 14px;"><strong>Please save this key immediately.</strong> We do not store the plaintext version.</p>
            
            <p>
                <a href="{dashboard_url}" style="color: #0b5bd7; text-decoration: none;">Dashboard</a> • 
                <a href="{quickstart_url}" style="color: #0b5bd7; text-decoration: none;">Quickstart</a> • 
                <a href="{docs_url}" style="color: #0b5bd7; text-decoration: none;">Docs</a>
            </p>
            
            <hr style="border: 0; border-top: 1px solid #e5e7eb; margin: 24px 0;">
            
            <p style="font-size: 12px; color: #6b7280;">
                {disclaimer}
            </p>
            <p style="font-size: 12px; color: #9ca3af;">
                Questions? Reply to this email or contact <a href="mailto:{from_email}" style="color: #9ca3af;">{from_email}</a>.
            </p>
        </div>
    </body>
    </html>
    """
    
    msg.set_content(text_body.strip())
    msg.add_alternative(html_body, subtype='html')

    # Send
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        if smtp_use_tls:
            server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
    
    print(f"[EMAIL] Sent onboarding email to {actual_recipient}")
