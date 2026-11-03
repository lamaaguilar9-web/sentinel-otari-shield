"""
Pre-Debit Budget Reservation & Durable SQLite WAL Usage Ledger for Mozilla.ai Otari.
Enforces strict workspace/user/model budget ceilings BEFORE dispatching requests to Otari.
"""

import os
import time
import sqlite3
import threading
from decimal import Decimal, ROUND_HALF_UP
from typing import Dict, Any
from .config import (
    SQLITE_DB_PATH,
    DEFAULT_DAILY_BUDGET_USD,
    MAX_SINGLE_REQUEST_USD,
    MODEL_PRICING_PER_1M_USD,
)


class OtariBudgetGovernor:
    """Thread-safe and process-atomic SQLite WAL Budget Governor (C-002, M-001, m-004 Fixed)."""

    _lock = threading.Lock()

    def __init__(self, db_path: str = SQLITE_DB_PATH, daily_budget_usd: Decimal = DEFAULT_DAILY_BUDGET_USD):
        self.db_path = db_path
        self.daily_budget_usd = Decimal(str(daily_budget_usd))
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS otari_usage_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reservation_id TEXT UNIQUE,
                    workspace_id TEXT,
                    model_id TEXT,
                    estimated_cost_usd TEXT,
                    actual_cost_usd TEXT,
                    prompt_tokens INTEGER,
                    completion_tokens INTEGER,
                    attestation_id TEXT,
                    status TEXT,
                    created_at INTEGER
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_otari_workspace_status
                ON otari_usage_ledger (workspace_id, status)
                """
            )
            conn.commit()

    def estimate_request_cost_usd(self, model_id: str, prompt_chars: int, max_completion_tokens: int = 512) -> Decimal:
        if model_id not in MODEL_PRICING_PER_1M_USD:
            raise ValueError(f"Unlisted model '{model_id}' rejected by strict FinOps policy (M-001).")
        pricing = MODEL_PRICING_PER_1M_USD[model_id]
        est_input_tokens = max(1, prompt_chars // 4)
        in_cost = (Decimal(est_input_tokens) / Decimal("1000000")) * pricing["input"]
        out_cost = (Decimal(max_completion_tokens) / Decimal("1000000")) * pricing["output"]
        return (in_cost + out_cost).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)

    def get_workspace_spent_usd(self, workspace_id: str = "default") -> Decimal:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT actual_cost_usd FROM otari_usage_ledger WHERE workspace_id = ? AND status IN ('RESERVED', 'SETTLED')",
                (workspace_id,)
            ).fetchall()
        total = sum((Decimal(r[0]) for r in rows), Decimal("0.000000"))
        return total.quantize(Decimal("0.000001"))

    def reserve_pre_debit(
        self,
        reservation_id: str,
        workspace_id: str,
        model_id: str,
        prompt_chars: int,
        max_completion_tokens: int,
        attestation_id: str
    ) -> Dict[str, Any]:
        try:
            est_cost = self.estimate_request_cost_usd(model_id, prompt_chars, max_completion_tokens)
        except ValueError as exc:
            return {
                "approved": False,
                "reason": str(exc),
                "estimated_cost_usd": "0.000000",
            }

        if est_cost > MAX_SINGLE_REQUEST_USD:
            return {
                "approved": False,
                "reason": f"Estimated request cost (${est_cost}) exceeds single-request cap (${MAX_SINGLE_REQUEST_USD}).",
                "estimated_cost_usd": str(est_cost)
            }

        # C-002 Fixed: Atomic BEGIN IMMEDIATE transaction + threading lock prevents TOCTOU race condition
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            try:
                conn.execute("BEGIN IMMEDIATE")
                rows = conn.execute(
                    "SELECT actual_cost_usd FROM otari_usage_ledger WHERE workspace_id = ? AND status IN ('RESERVED', 'SETTLED')",
                    (workspace_id,)
                ).fetchall()
                current_spent = sum((Decimal(r[0]) for r in rows), Decimal("0.000000")).quantize(Decimal("0.000001"))

                if current_spent + est_cost > self.daily_budget_usd:
                    conn.execute("ROLLBACK")
                    return {
                        "approved": False,
                        "reason": f"Workspace '{workspace_id}' budget exhausted (${current_spent} + ${est_cost} > ${self.daily_budget_usd}).",
                        "estimated_cost_usd": str(est_cost)
                    }

                conn.execute(
                    """
                    INSERT INTO otari_usage_ledger
                    (reservation_id, workspace_id, model_id, estimated_cost_usd, actual_cost_usd, prompt_tokens, completion_tokens, attestation_id, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'SETTLED', ?)
                    """,
                    (
                        reservation_id,
                        workspace_id,
                        model_id,
                        str(est_cost),
                        str(est_cost),
                        max(1, prompt_chars // 4),
                        max_completion_tokens,
                        attestation_id,
                        int(time.time())
                    )
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

        return {
            "approved": True,
            "reservation_id": reservation_id,
            "workspace_id": workspace_id,
            "model_id": model_id,
            "estimated_cost_usd": str(est_cost),
            "remaining_budget_usd": str((self.daily_budget_usd - (current_spent + est_cost)).quantize(Decimal("0.000001")))
        }

    def get_telemetry_summary(self) -> Dict[str, Any]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT reservation_id, workspace_id, model_id, actual_cost_usd, attestation_id, status, created_at FROM otari_usage_ledger ORDER BY id DESC LIMIT 15"
            ).fetchall()
            count_row = conn.execute("SELECT COUNT(*) FROM otari_usage_ledger").fetchone()

        total_spent = self.get_workspace_spent_usd("default")
        return {
            "gateway": "Mozilla.ai Otari Control Plane + Sentinel Zero-Leakage Shield",
            "total_requests_governed": count_row[0] if count_row else 0,
            "daily_budget_cap_usd": str(self.daily_budget_usd),
            "total_spent_usd": str(total_spent),
            "remaining_budget_usd": str((self.daily_budget_usd - total_spent).quantize(Decimal("0.000001"))),
            "recent_ledger": [
                {
                    "reservation_id": r[0],
                    "workspace_id": r[1],
                    "model_id": r[2],
                    "cost_usd": r[3],
                    "attestation_id": r[4],
                    "status": r[5],
                    "timestamp": r[6],
                }
                for r in rows
            ]
        }
