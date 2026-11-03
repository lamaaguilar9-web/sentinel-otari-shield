"""
Configuration & Constants for Sentinel Otari Shield.
Built on Mozilla.ai Otari (https://github.com/mozilla-ai/otari) Open-Source LLM Control Plane.
Zero hardcoded secrets — all credentials loaded strictly via environment variables.
"""

import os
from decimal import Decimal

# Mozilla.ai Otari Control Plane Endpoints
OTARI_BASE_URL: str = os.getenv("OTARI_BASE_URL", "http://localhost:8000/api/v1").rstrip("/")
OTARI_VIRTUAL_KEY: str = os.getenv("OTARI_VIRTUAL_KEY", "")
OTARI_PROVIDER_ACCOUNT_PEPPER: str = os.getenv("OTARI_PROVIDER_ACCOUNT_PEPPER", "")

# Default Open-Weight Models routed via Otari
DEFAULT_OPEN_WEIGHT_MODEL: str = os.getenv(
    "OTARI_DEFAULT_MODEL",
    "openrouter:nvidia/nemotron-3-ultra-550b-a55b:free"
)

# Budget Governance & Pre-Debit Reservation Limits (USD)
DEFAULT_DAILY_BUDGET_USD: Decimal = Decimal(os.getenv("OTARI_DAILY_BUDGET_USD", "25.00"))
MAX_SINGLE_REQUEST_USD: Decimal = Decimal(os.getenv("OTARI_MAX_SINGLE_REQUEST_USD", "0.50"))

# SQLite WAL Durable Ledger Path
SQLITE_DB_PATH: str = os.getenv(
    "OTARI_SHIELD_DB_PATH",
    os.path.join(os.path.dirname(__file__), "data", "otari_shield_ledger.db")
)

# Pricing per 1M tokens (USD) for Otari Pre-Debit Estimation
MODEL_PRICING_PER_1M_USD = {
    "openrouter:nvidia/nemotron-3-ultra-550b-a55b:free": {
        "input": Decimal("0.00"),
        "output": Decimal("0.00"),
        "tier": "OPEN_WEIGHT_FREE"
    },
    "openrouter:thinkingmachines/inkling:free": {
        "input": Decimal("0.00"),
        "output": Decimal("0.00"),
        "tier": "OPEN_WEIGHT_FREE"
    },
    "ollama:llama3.3:70b": {
        "input": Decimal("0.00"),
        "output": Decimal("0.00"),
        "tier": "LOCAL_SELF_HOSTED"
    },
    "openai:gpt-4o-mini": {
        "input": Decimal("0.15"),
        "output": Decimal("0.60"),
        "tier": "COMMERCIAL_METERED"
    },
    "anthropic:claude-3-5-sonnet": {
        "input": Decimal("3.00"),
        "output": Decimal("15.00"),
        "tier": "COMMERCIAL_METERED"
    }
}
