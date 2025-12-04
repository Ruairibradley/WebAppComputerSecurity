from flask_mail import Message
from flask import current_app
from pathlib import Path
from datetime import datetime
from . import mail

OUTBOX = Path("Outbox.txt")

def _write_outbox(subject: str, to_addr: str, body: str):
    stamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    msg = (
        f"\n--- EMAIL (fallback) ---\n"
        f"Time: {stamp}\nTo: {to_addr}\nSubject: {subject}\n\n{body}\n"
        f"------------------------\n"
    )
    print(msg)
    try:
        prev = OUTBOX.read_text(encoding="utf-8") if OUTBOX.exists() else ""
        OUTBOX.write_text(prev + msg, encoding="utf-8")
    except Exception:
        pass

def send_email(subject: str, to_addr: str, body: str) -> None:
    """
    Send an email with Flask-Mail using MAIL_* config.
    On any exception, write to Outbox.txt as evidence.
    """
    try:
        msg = Message(subject=subject, recipients=[to_addr], body=body)
        
        default_sender = current_app.config.get("MAIL_DEFAULT_SENDER")
        if default_sender:
            msg.sender = default_sender
        mail.send(msg)
    except Exception:
        _write_outbox(subject, to_addr, body)


def send_console_email(subject: str, to_addr: str, body: str) -> None:
    send_email(subject, to_addr, body)
