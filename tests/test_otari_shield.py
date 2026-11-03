"""Automated Verification Suite for Sentinel Otari Shield v1.0.0 (Includes Hermes Audit Fixes)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from fastapi.testclient import TestClient

from otari_shield.budget_governor import OtariBudgetGovernor
from otari_shield.redactor import ZeroLeakageRedactor
from otari_shield.api import app


def test_redactor_sanitizes_pii_and_international_tax_ids() -> None:
    redactor = ZeroLeakageRedactor(block_on_crypto_keys=True)
    raw = (
        "Client John Doe SSN 123-45-6789, EIN 12-3456789, RFC XAXX010101000, "
        "NIT 900.123.456-7, card 4532-0151-1283-0366."
    )
    res = redactor.inspect_and_sanitize(raw)
    assert res.approved is True
    assert res.action == "REDACTED_AND_SANITIZED"
    assert "123-45-6789" not in res.sanitized_text
    assert "12-3456789" not in res.sanitized_text
    assert "XAXX010101000" not in res.sanitized_text
    assert "900.123.456-7" not in res.sanitized_text
    assert "4532-0151-1283-0366" not in res.sanitized_text
    assert "[REDACTED_US_SSN]" in res.sanitized_text
    assert "[REDACTED_US_EIN]" in res.sanitized_text
    assert "[REDACTED_MX_RFC]" in res.sanitized_text
    assert "[REDACTED_LATAM_NIT]" in res.sanitized_text
    assert "[REDACTED_CARD_PAN]" in res.sanitized_text
    assert res.attestation_id.startswith("OTARI-CLEAN-")


def test_redactor_blocks_evm_openai_anthropic_aws_secrets() -> None:
    redactor = ZeroLeakageRedactor(block_on_crypto_keys=True)
    for secret in [
        "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
        "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
        "Bearer sk-ant-api01-abcdefghijklmnopqrstuvwxyz",
        "AKIAIOSFODNN7EXAMPLE",
    ]:
        res = redactor.inspect_and_sanitize(f"Credentials: {secret}")
        assert res.approved is False
        assert res.action == "BLOCKED_CRITICAL_SECRET"


def test_budget_governor_atomic_concurrency_protection(tmp_path) -> None:
    db_path = str(tmp_path / "test_otari_concurrent.db")
    # Budget allows exactly ONE request (~$0.006300), not two
    gov = OtariBudgetGovernor(db_path=db_path, daily_budget_usd=Decimal("0.010000"))

    def worker(idx: int):
        return gov.reserve_pre_debit(
            reservation_id=f"rsv-conc-{idx}",
            workspace_id="default",
            model_id="anthropic:claude-3-5-sonnet",
            prompt_chars=400,
            max_completion_tokens=400,
            attestation_id=f"OTARI-CLEAN-{idx}",
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(worker, range(4)))

    approved_count = sum(1 for r in results if r["approved"])
    assert approved_count == 1  # Atomic lock prevents TOCTOU race condition


def test_fastapi_endpoints_and_otari_shield_workflow() -> None:
    client = TestClient(app)

    # 1. Health check
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    # 2. Unauthorized reset fails with 401
    unauth = client.post("/api/v1/budget/reset?workspace_id=default&daily_budget_usd=0.01")
    assert unauth.status_code == 401

    # 3. Authorized reset succeeds
    reset = client.post(
        "/api/v1/budget/reset?workspace_id=default&daily_budget_usd=0.01",
        headers={"X-Otari-Admin-Token": "otari-admin-local-dev"},
    )
    assert reset.status_code == 200

    # 4. Valid request with PII gets redacted and succeeds
    resp = client.post(
        "/api/v1/chat/completions",
        json={
            "model": "openai:gpt-4o-mini",
            "workspace_id": "default",
            "max_tokens": 256,
            "messages": [
                {
                    "role": "user",
                    "content": "Verify tax lot for SSN 123-45-6789 and card 4532-0151-1283-0366",
                }
            ],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "otari_shield" in body
    assert len(body["otari_shield"]["findings"]) == 2

    # 5. Request with EVM private key is blocked with HTTP 403
    secret_resp = client.post(
        "/api/v1/chat/completions",
        json={
            "model": "openai:gpt-4o-mini",
            "workspace_id": "default",
            "max_tokens": 128,
            "messages": [
                {
                    "role": "user",
                    "content": "My key is 0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
                }
            ],
        },
    )
    assert secret_resp.status_code == 403
    assert secret_resp.json()["error"]["code"] == "OTARI_SHIELD_SECRET_BLOCKED"

    # 6. Request exceeding remaining $0.01 budget is blocked with HTTP 429
    over_budget = client.post(
        "/api/v1/chat/completions",
        json={
            "model": "anthropic:claude-3-5-sonnet",
            "workspace_id": "default",
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": "Summarize general ledger."}],
        },
    )
    assert over_budget.status_code == 429
    assert over_budget.json()["error"]["code"] == "OTARI_SHIELD_BUDGET_EXCEEDED"
