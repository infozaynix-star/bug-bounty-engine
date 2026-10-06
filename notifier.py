import requests
import html
import logging
from urllib.parse import urlsplit

from pipeline import may_send_telegram, redact_secrets
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

logger = logging.getLogger(__name__)


def send_telegram_alert(payload: dict) -> bool:
    """
    إرسال تنبيه منظم لمجموعتك على تليجرام دون التعرض لمشاكل كسر التنسيق.
    """
    if not may_send_telegram(payload):
        print("Alert blocked: finding did not pass evidence, scope, and confidence gates.")
        return False

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("⚠️ لم يتم ضبط TELEGRAM_BOT_TOKEN أو TELEGRAM_CHAT_ID في .env")
        return False

    company = html.escape(str(payload.get("company", "N/A")))
    repo = html.escape(str(payload.get("repo", "N/A")))
    vuln_type = html.escape(str(payload.get("type", "Security Finding")))
    confidence = html.escape(str(payload.get("confidence_level", "LOW")))
    ai_reason = html.escape(redact_secrets(str(payload.get("ai_reason", "N/A"))))
    source_file = html.escape(str(payload.get("file", "N/A")))
    line = html.escape(str(payload.get("line", "N/A")))
    context = html.escape(redact_secrets(str(payload.get("context", ""))[:450]))
    raw_commit_url = str(payload.get("commit_url", ""))
    parsed_commit_url = urlsplit(raw_commit_url)
    if (
        parsed_commit_url.scheme != "https"
        or parsed_commit_url.hostname != "github.com"
    ):
        raw_commit_url = "#"
    commit_url = html.escape(raw_commit_url, quote=True)

    # تنسيق نص الرسالة باستخدام HTML الآمن
    message = f"""<b>🚨 [HIGH-CONFIDENCE FINDING]</b>

🏢 <b>Company:</b> <code>{company}</code>
📁 <b>Repository:</b> <code>{repo}</code>
🔑 <b>Candidate Type:</b> <code>{vuln_type}</code>
📄 <b>Source:</b> <code>{source_file}:{line}</code>
🎯 <b>Confidence:</b> <code>{confidence}</code>

📝 <b>AI Evaluation:</b>
<i>{ai_reason}</i>

🔍 <b>Context Snippet:</b>
<pre><code>{context}</code></pre>

🔗 <a href="{commit_url}">View Commit Changes</a>
"""

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }

    try:
        response = requests.post(url, json=data, timeout=10)
        if response.status_code == 200:
            return True
        logger.warning("Telegram alert request failed (HTTP %s)", response.status_code)
        return False
    except requests.RequestException as error:
        logger.error("Telegram alert request failed (%s)", type(error).__name__)
        return False