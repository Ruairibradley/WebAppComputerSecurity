from pathlib import Path
from datetime import datetime

# txt file for links to reset / verify as not hosting online no real email sending. 
OUTBOX = Path("Outbox.txt")

def send_console_email(subject: str, to_addr: str, body: str) -> None:
    """
    Simulated email sending by printing to console and appending to Outbox.txt.
    args:
        subject: str
        to_addr: str
        body: str
    returns: 
        None
    """
    stamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    msg = (
        f"\n--- EMAIL (demo) ---\n"
        f"Time: {stamp}\nTo: {to_addr}\nSubject: {subject}\n\n{body}\n"
        f"--------------------\n"
    )
    print(msg)  # console output (demo purposes)
    try:
        prev = OUTBOX.read_text(encoding="utf-8") if OUTBOX.exists() else ""
        OUTBOX.write_text(prev + msg, encoding="utf-8")
    except Exception:
        pass
