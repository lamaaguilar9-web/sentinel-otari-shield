# AUDITORÍA DE SEGURIDAD — SENTINEL OTARI SHIELD v1.0.0
**Proyecto:** Mozilla.ai Otari Hackathon ($1,000 USD)  
**Ubicación:** `C:\Users\luis\.gemini\antigravity\scratch\sentinel-otari-shield`  
**Fecha:** 2026-11-01  
**Auditor:** Hermes (Modo Solo Lectura / Auditor Estricto)  
**Scope:** 6 archivos core + tests  

---

## RESUMEN EJECUTIVO

| Categoría | Hallazgos | Severidad |
|-----------|-----------|-----------|
| 🔴 **CRÍTICO** | 2 | Bypass en ZeroLeakageRedactor + SQLite WAL race condition |
| 🟠 **MAYOR** | 3 | Hardcoded fallback pricing + CORS wildcard + Missing auth on budget reset |
| 🟡 **MENOR** | 4 | PII regex gaps + Missing rate limiting + No input validation on workspace_id + Logging gaps |

**Veredicto:** ❌ **NO APROBADO para GitHub público** — Requiere correcciones críticas antes de push.

---

## 🔴 HALLÁZGOS CRÍTICOS

### C-001: Bypass en ZeroLeakageRedactor — API Secret Token Regex Incompleto
**Archivo:** `otari_shield/redactor.py` líneas 36, 73-81  
**Severidad:** 🔴 CRÍTICO  

**Descripción:** La regex `API_SECRET_TOKEN_RE` (línea 36) no captura formatos comunes de API keys:
```python
API_SECRET_TOKEN_RE = re.compile(r"\b(?:sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{30,}|tk-[a-zA-Z0-9_-]{16,})\b")
```

**Falta detección de:**
- OpenAI `sk-proj-...` (project-scoped keys)
- Anthropic `sk-ant-...` 
- AWS `AKIA...` / `ASIA...`
- Google Cloud `AIza...`
- Generic `api_key=...` / `Bearer ...` en headers

**PoC de Bypass:**
```python
# Estos NO son detectados:
"Use key sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"  # OpenAI project key
"Authorization: Bearer sk-ant-api01-xxxxxxxxxxxxx"      # Anthropic
"aws_access_key_id=AKIAIOSFODNN7EXAMPLE"                # AWS
```

**Fix Requerido:** Ampliar regex o usar lista denylist extensible.

---

### C-002: SQLite WAL Race Condition en Budget Governor — TOCTOU
**Archivo:** `otari_shield/budget_governor.py` líneas 58-90, 92-111  
**Severidad:** 🔴 CRÍTICO  

**Descripción:** Patrón **Check-Then-Act** no atómico entre `get_workspace_spent_usd()` (línea 58) y `reserve_pre_debit()` INSERT (línea 92-111).

**Vulnerabilidad:** Dos requests concurrentes leen `current_spent` igual → ambos pasan check → ambos insertan → **gasto total > daily_budget_usd**.

**PoC Concurrencia:**
```python
# Thread A y B simultáneos:
current_spent = get_workspace_spent_usd()  # Ambos leen $0.00
# Ambos pasan: $0 + $0.005 < $0.01
# Ambos INSERT → Total gastado = $0.01 > $0.01 budget
```

**Fix Requerido:** Transacción atómica con `SELECT ... FOR UPDATE` o constraint UNIQUE + check en DB.

---

## 🟠 HALLÁZGOS MAYORES

### M-001: Hardcoded Fallback Pricing en Budget Governor
**Archivo:** `otari_shield/budget_governor.py` líneas 49-52  
**Severidad:** 🟠 MAYOR  

```python
pricing = MODEL_PRICING_PER_1M_USD.get(
    model_id,
    {"input": Decimal("0.50"), "output": Decimal("1.50"), "tier": "CUSTOM_METERED"}  # HARDCODED
)
```

**Riesgo:** Modelos no listados (ej. nuevos modelos OpenRouter) usan pricing genérico → **subestimación/ sobreestimación** de costo → bypass de budget o bloqueo falso.

**Fix:** Rechazar modelos no listados o exigir pricing explícito en config.

---

### M-002: CORS Wildcard + Missing Auth en Endpoints Críticos
**Archivo:** `otari_shield/api.py` líneas 52-57, 111-128  

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 🟠 WILDCARD EN PRODUCCIÓN
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Endpoint sin auth:** `/api/v1/budget/reset` (línea 111) — **cualquiera puede resetear budgets** de cualquier workspace.

**Fix:** Requerir `Authorization: Bearer <admin_token>` en `/budget/reset` y restringir CORS a dominios conocidos.

---

### M-003: Regex PII Incompleta — Falta EIN / RFC / NIT
**Archivo:** `otari_shield/redactor.py` líneas 39-41  

```python
US_SSN_RE = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
CREDIT_CARD_RE = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
EMAIL_PII_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
```

**Faltan identificadores fiscales internacionales:**
- **EIN (US Employer):** `XX-XXXXXXX`
- **RFC (México):** `XXXX000000XXX`
- **NIT (Colombia/Chile):** `XXX.XXX.XXX-X`
- **RUT (Chile):** `XX.XXX.XXX-X`

**Impacto:** Workloads CPA internacionales **filtran identificadores fiscales**.

---

## 🟡 HALLÁZGOS MENORES

| ID | Archivo | Línea | Hallazgo |
|----|---------|-------|----------|
| m-001 | `redactor.py` | 41 | `EMAIL_PII_RE` captura emails en código/ejemplos (falsos positivos) |
| m-002 | `api.py` | 132 | Sin rate limiting en `/chat/completions` (DoS vector) |
| m-003 | `api.py` | 132 | `workspace_id` sin validación (path traversal teórico via `../../`) |
| m-004 | `budget_governor.py` | 58-65 | Sin índice en `workspace_id` + `status` (full scan en scale) |
| m-005 | `gateway_client.py` | 43-49 | Silent fallback a sandbox sin logging de error real |

---

## 🧪 TESTS — Cobertura Insuficiente

| Test | Archivo | Línea | Gap |
|------|---------|-------|-----|
| `test_redactor_sanitizes_pii_and_generates_attestation` | `test_otari_shield.py` | 14-26 | No testa EIN/RFC/NIT |
| `test_redactor_blocks_evm_and_api_secrets` | `test_otari_shield.py` | 29-41 | No testa `sk-proj-`, `sk-ant-`, AWS keys |
| `test_budget_governor_pre_debit_and_hard_ceiling` | `test_otari_shield.py` | 44-69 | **No testa concurrencia** (race condition) |
| `test_fastapi_endpoints_and_otari_shield_workflow` | `test_otari_shield.py` | 71-132 | No testa rate limiting, CORS, auth en `/budget/reset` |

---

## 📋 PLAN DE CORRECCIÓN PRIORITARIO

### 🔴 ANTES DE PUSH A GITHUB (Bloqueadores)

| Orden | Acción | Archivo | Línea |
|-------|--------|---------|-------|
| 1 | Fix API_SECRET_TOKEN_REGEX completo | `redactor.py` | 36 |
| 2 | Atomic budget reservation (DB constraint + transaction) | `budget_governor.py` | 58-111 |
| 3 | Auth required en `/api/v1/budget/reset` | `api.py` | 111-128 |
| 4 | Restringir CORS a dominios específicos | `api.py` | 52-57 |

### 🟠 ESTA SEMANA

| Acción | Archivo | Línea |
|--------|---------|-------|
| Rechazar modelos sin pricing explícito | `budget_governor.py` | 49-52 |
| Añadir EIN/RFC/NIT regex | `redactor.py` | 38-41 |
| Rate limiting en `/chat/completions` | `api.py` | 132 |
| Validar `workspace_id` (alphanum + guiones) | `api.py` | 132 |

### 🟡 ESTE MES

| Acción | Archivo |
|--------|---------|
| Índice compuesto en `workspace_id, status` | `budget_governor.py` |
| Rate limiting middleware | `api.py` |
| Tests de concurrencia (pytest-asyncio) | `tests/test_otari_shield.py` |
| Logging estructurado (structlog) | `gateway_client.py`, `api.py` |

---

## ✅ CHECKLIST PARA GITHUB PÚBLICO

- [ ] **C-001** Fixed: API secret regex completo
- [ ] **C-002** Fixed: Atomic budget reservation
- [ ] **M-001** Fixed: No hardcoded fallback pricing
- [ ] **M-002** Fixed: Auth en `/budget/reset` + CORS restrictivo
- [ ] **M-003** Fixed: EIN/RFC/NIT regex added
- [ ] Tests de concurrencia pasando
- [ ] Rate limiting implementado
- [ ] `.env.example` actualizado (sin secrets)
- [ ] `README.md` con badges de seguridad actualizados
- [ ] `SECURITY.md` con disclosure policy

---

## 📝 VEREDICTO FINAL

> **NO APROBADO para GitHub público en estado actual.**
> 
> **2 hallazgos CRÍTICOS** (bypass redactor + race condition budget) permiten:
> 1. Filtrar claves privadas/API keys a proveedores LLM externos
> 2. Exceder budget diario via concurrencia → costo financiero real
> 
> **Correcciones mínimas estimadas: 4-6 horas de desarrollo + 2 horas testing.**
> 
> Una vez aplicados fixes críticos y validados tests de concurrencia, **APROBADO para release.**

---

**Firma:** Hermes (Sentinel Fleet Technologies)  
**Modo:** Solo Lectura / Auditor Estricto  
**Fecha:** 2026-11-01  
**Archivo:** `C:\Users\luis\.gemini\antigravity\scratch\sentinel-otari-shield\AUDITORIA_HERMES_OTARI.md`