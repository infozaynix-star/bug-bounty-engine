import os
from dotenv import load_dotenv

load_dotenv()


def parse_target_repositories(value: str) -> set[str]:
    return {
        repository.strip().casefold()
        for repository in value.split(",")
        if repository.strip()
    }


def github_token_from_environment(environment: dict[str, str]) -> str:
    return (
        environment.get("GITHUB_TOKEN")
        or environment.get("MY_GITHUB_TOKEN")
        or environment.get("My_GITHUB_TOKEN", "")
    ).strip()


GITHUB_TOKEN = github_token_from_environment(os.environ)
My_GITHUB_TOKEN = GITHUB_TOKEN
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "").strip() or "openai/gpt-oss-120b"
TARGET_REPOS = parse_target_repositories(os.getenv("TARGET_REPOS", ""))

GITHUB_API_URL = "https://api.github.com"
GITHUB_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "BugBountyEngine/1.0"
}

TARGET_PROGRAMS = [
    {"name": "Shopify", "org": "Shopify"},
    {"name": "Vercel", "org": "vercel"},
    {"name": "GitHub", "org": "github"},
    {"name": "GitLab", "org": "gitlab-org"},
    {"name": "Automattic", "org": "Automattic"},
    {"name": "Cloudflare", "org": "cloudflare"},
    {"name": "Supabase", "org": "supabase"},
    {"name": "HashiCorp", "org": "hashicorp"},
    {"name": "Docker", "org": "docker"},
    {"name": "DigitalOcean", "org": "digitalocean"},
    {"name": "Stripe", "org": "stripe"},
    {"name": "PayPal", "org": "paypal"},
    {"name": "Square (Block)", "org": "square"},
    {"name": "Meta (Facebook)", "org": "facebook"},
    {"name": "Microsoft", "org": "microsoft"},
    {"name": "Google", "org": "google"},
    {"name": "Netflix", "org": "Netflix"},
    {"name": "Spotify", "org": "spotify"},
    {"name": "Elastic", "org": "elastic"},
    {"name": "Coinbase", "org": "coinbase"}
]

# توافق مع المسمى الجديد والقديم
TARGET_COMPANIES = TARGET_PROGRAMS