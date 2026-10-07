import os
import hmac
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client


# =========================
# Utils
# =========================

def get_env(name: str, required: bool = True, default: Optional[str] = None) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value or ""


# =========================
# Environment
# =========================

SUPABASE_URL = get_env("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = get_env("SUPABASE_SERVICE_ROLE_KEY")

# Secret partagé FeexPay, transmis via un header statique (type "Bearer"
# dans le dashboard FeexPay). Ce n'est PAS une signature HMAC du corps :
# FeexPay envoie simplement la valeur telle quelle, sans calcul de hash.
# La même valeur doit être configurée des deux côtés.
FEEPAY_WEBHOOK_SECRET = os.environ.get("FEEPAY_WEBHOOK_SECRET", "")

# Nom du header porte du secret. "Authorization" si Header type = Bearer,
# sinon le nom du header choisi dans le dashboard.
FEEPAY_WEBHOOK_HEADER = os.environ.get("FEEPAY_WEBHOOK_HEADER", "Authorization")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# =========================
# App
# =========================

app = FastAPI(title="FeexPay Webhook", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# =========================
# Routes système
# =========================

@app.api_route("/", methods=["GET", "POST"])
def root() -> Dict[str, Any]:
    """
    Route racine acceptant GET et POST
    (nécessaire pour les health-checks des plateformes)
    """
    return {
        "ok": True,
        "service": "feexpay-webhook",
        "version": "1.0.0"
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "healthy"}


# =========================
# Sécurité signature
# =========================

def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _extract_secret(header_value: str) -> str:
    """
    Normalise la valeur du header.

    Le dashboard FeeXPay ("Header type: Bearer") peut envoyer soit la valeur
    brute telle qu'elle est saisie, soit le préfixe "Bearer " ajouté par
    FeeXPay. On accepte les deux formes pour ne pas dépendre de ce choix.
    """
    value = (header_value or "").strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    return value


def verify_webhook_secret(provided_value: Optional[str]) -> None:
    """
    Vérifie le secret partagé transmis dans le header.

    NOTE : FeexPay n'envoie pas de signature HMAC du corps de la requête,
    mais une valeur statique définie dans le dashboard. On compare donc
    directement la valeur reçue au secret attendu.
    """
    # Si aucun secret n'est configuré, on skip (mode permissif)
    if not FEEPAY_WEBHOOK_SECRET:
        return

    if not provided_value:
        raise HTTPException(status_code=401, detail="Missing authorization header")

    if not constant_time_compare(
        _extract_secret(provided_value), FEEPAY_WEBHOOK_SECRET
    ):
        raise HTTPException(status_code=401, detail="Invalid webhook secret")


# =========================
# Business logic
# =========================

def map_payment_status(provider_status: str) -> str:
    normalized = (provider_status or "").upper()

    if normalized in ("SUCCESS", "SUCCESSFUL", "COMPLETED"):
        return "confirmed"
    if normalized in ("FAIL", "FAILED", "CANCELED", "CANCELLED"):
        return "failed"
    return "pending"


def upsert_order(payload: Dict[str, Any]) -> None:
    tx_id = payload.get("transaction_id") or payload.get("reference")
    order_ref = payload.get("order_number") or payload.get("reference")
    provider_status = payload.get("status") or payload.get("payment_status")
    provider_name = payload.get("payment_provider") or "feexpay"

    if not tx_id and not order_ref:
        raise HTTPException(
            status_code=400,
            detail="transaction_id or order_number is required"
        )

    status_app = map_payment_status(provider_status or "")

    # 1️⃣ Update par order_number
    if order_ref:
        existing = (
            supabase.table("orders")
            .select("id")
            .eq("order_number", order_ref)
            .limit(1)
            .execute()
        )
        if existing.data:
            supabase.table("orders").update({
                "transaction_id": tx_id,
                "payment_reference": order_ref,
                "payment_provider": provider_name,
                "payment_status": provider_status,
                "status": status_app,
            }).eq("order_number", order_ref).execute()
            return

    # 2️⃣ Update par transaction_id
    if tx_id:
        existing_tx = (
            supabase.table("orders")
            .select("id")
            .eq("transaction_id", tx_id)
            .limit(1)
            .execute()
        )
        if existing_tx.data:
            supabase.table("orders").update({
                "payment_reference": order_ref,
                "payment_provider": provider_name,
                "payment_status": provider_status,
                "status": status_app,
            }).eq("transaction_id", tx_id).execute()
            return

    # 3️⃣ Insert minimal si inexistant
    supabase.table("orders").insert({
        "order_number": order_ref,
        "transaction_id": tx_id,
        "payment_reference": order_ref,
        "payment_provider": provider_name,
        "payment_status": provider_status,
        "status": status_app,
        "total_amount": payload.get("amount"),
        "notes": "Created by FeexPay webhook",
    }).execute()


# =========================
# Webhook FeexPay
# =========================

@app.post("/webhooks/feexpay")
async def feexpay_webhook(request: Request) -> JSONResponse:
    # Secret partagé porté par le header défini dans le dashboard FeeXPay.
    # On accepte aussi les anciens noms de headers signature pour ne pas
    # casser un ancien client, mais ils ne sont plus utilisés par FeeXPay.
    provided_value = (
        request.headers.get(FEEPAY_WEBHOOK_HEADER)
        or request.headers.get("X-Feexpay-Signature")
        or request.headers.get("X-Signature")
    )

    verify_webhook_secret(provided_value)

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    try:
        upsert_order(payload)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return JSONResponse({"ok": True})
