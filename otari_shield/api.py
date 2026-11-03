"""FastAPI Server for Sentinel Otari Shield v1.0.0.

Provides an OpenAI-compatible `/api/v1/chat/completions` proxy endpoint wrapped
with Zero-Leakage PII/Secret Redaction, Pre-Debit Budget Governance, and an
Interactive Judge & Enterprise Audit Console (`/`).
"""
from __future__ import annotations

import os
import re
import sqlite3
import time
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .budget_governor import OtariBudgetGovernor
from .config import (
    DEFAULT_DAILY_BUDGET_USD,
    DEFAULT_OPEN_WEIGHT_MODEL,
    OTARI_BASE_URL,
    OTARI_VIRTUAL_KEY,
    SQLITE_DB_PATH,
)
from .gateway_client import OtariGatewayClient
from .redactor import ZeroLeakageRedactor

ADMIN_RESET_TOKEN: str = os.getenv("OTARI_ADMIN_RESET_TOKEN", "otari-admin-local-dev")
ALLOWED_ORIGINS: List[str] = [
    o.strip()
    for o in os.getenv("OTARI_ALLOWED_ORIGINS", "http://localhost:8090,http://127.0.0.1:8090").split(",")
    if o.strip()
]
WORKSPACE_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

redactor = ZeroLeakageRedactor(block_on_crypto_keys=True)
governor = OtariBudgetGovernor(
    db_path=SQLITE_DB_PATH,
    daily_budget_usd=DEFAULT_DAILY_BUDGET_USD,
)
gateway_client = OtariGatewayClient(
    base_url=OTARI_BASE_URL,
    virtual_key=OTARI_VIRTUAL_KEY,
)

app = FastAPI(
    title="Sentinel Otari Shield API",
    description=(
        "Enterprise Zero-Leakage PII/Secret Firewall & Pre-Debit FinOps Governor "
        "built on Mozilla.ai Otari LLM Gateway."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Otari-Admin-Token"],
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class ChatMessage(BaseModel):
    role: str = Field(..., description="Message role: system, user, or assistant")
    content: str = Field(..., description="Message text content")


class ChatCompletionRequest(BaseModel):
    model: str = Field(
        default=DEFAULT_OPEN_WEIGHT_MODEL,
        description="Provider/model identifier routed via Mozilla.ai Otari Gateway",
    )
    messages: List[ChatMessage] = Field(..., min_length=1)
    workspace_id: str = Field(
        default="default",
        pattern=r"^[a-zA-Z0-9_-]{1,64}$",
        description="Otari Workspace / Virtual Key ID for tenant budget isolation",
    )
    max_tokens: int = Field(
        default=512,
        ge=1,
        le=8192,
        description="Maximum completion tokens reserved before upstream dispatch",
    )


@app.get("/")
def serve_console() -> FileResponse:
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Console UI not found")
    return FileResponse(str(index_path))


@app.get("/health")
def health_check() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "sentinel-otari-shield",
        "version": "1.0.0",
        "otari_gateway_url": OTARI_BASE_URL,
        "default_model": DEFAULT_OPEN_WEIGHT_MODEL,
        "daily_budget_usd": str(governor.daily_budget_usd),
    }


@app.get("/api/v1/telemetry")
def get_telemetry() -> Dict[str, Any]:
    return governor.get_telemetry_summary()


@app.post("/api/v1/budget/reset")
def reset_workspace_budget(
    workspace_id: str = "default",
    daily_budget_usd: Optional[float] = None,
    x_otari_admin_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if not WORKSPACE_ID_RE.match(workspace_id):
        raise HTTPException(status_code=400, detail="Invalid workspace_id format")
    if x_otari_admin_token != ADMIN_RESET_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized: valid X-Otari-Admin-Token required")

    if daily_budget_usd is not None:
        governor.daily_budget_usd = Decimal(str(daily_budget_usd))
    with sqlite3.connect(governor.db_path) as conn:
        conn.execute(
            "DELETE FROM otari_usage_ledger WHERE workspace_id = ?",
            (workspace_id,),
        )
        conn.commit()
    return {
        "status": "reset",
        "workspace_id": workspace_id,
        "telemetry": governor.get_telemetry_summary(),
    }


@app.post("/api/v1/chat/completions")
def create_chat_completion(
    req: ChatCompletionRequest,
    authorization: Optional[str] = Header(default=None),
) -> JSONResponse:
    t0 = time.perf_counter()

    sanitized_messages: List[Dict[str, str]] = []
    all_findings: List[Dict[str, str]] = []
    blocked_secret = False
    last_attestation = ""
    total_chars = 0

    for msg in req.messages:
        scan = redactor.inspect_and_sanitize(msg.content)
        last_attestation = scan.attestation_id
        all_findings.extend(scan.findings)
        if not scan.approved:
            blocked_secret = True
        sanitized_messages.append({"role": msg.role, "content": scan.sanitized_text})
        total_chars += len(scan.sanitized_text)

    if blocked_secret:
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": "OTARI_SHIELD_SECRET_BLOCKED",
                    "message": (
                        "Outbound request blocked by Sentinel Otari Shield before reaching "
                        "external LLM provider: critical cryptographic secret detected."
                    ),
                    "findings": all_findings,
                    "attestation_id": last_attestation,
                    "latency_ms": latency_ms,
                }
            },
        )

    reservation_id = f"rsv-{uuid.uuid4().hex[:12]}"
    reservation = governor.reserve_pre_debit(
        reservation_id=reservation_id,
        workspace_id=req.workspace_id,
        model_id=req.model,
        prompt_chars=total_chars,
        max_completion_tokens=req.max_tokens,
        attestation_id=last_attestation,
    )
    if not reservation["approved"]:
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return JSONResponse(
            status_code=429,
            content={
                "error": {
                    "code": "OTARI_SHIELD_BUDGET_EXCEEDED",
                    "message": reservation["reason"],
                    "estimated_cost_usd": reservation["estimated_cost_usd"],
                    "attestation_id": last_attestation,
                    "latency_ms": latency_ms,
                }
            },
        )

    upstream_response = gateway_client.chat_completions(
        messages=sanitized_messages,
        model=req.model,
        max_tokens=req.max_tokens,
        workspace_id=req.workspace_id,
    )
    latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    return JSONResponse(
        status_code=200,
        content={
            **upstream_response,
            "otari_shield": {
                "attestation_id": last_attestation,
                "findings": all_findings,
                "sanitized_messages": sanitized_messages,
                "budget_reservation": reservation,
                "latency_ms": latency_ms,
            },
        },
    )
