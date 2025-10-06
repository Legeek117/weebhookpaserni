import os
import hmac
import hashlib
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client


def get_env(name: str, required: bool = True, default: Optional[str] = None) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value or ""


SUPABASE_URL = get_env("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = get_env("SUPABASE_SERVICE_ROLE_KEY")
# Optional: if FeexPay provides a signature header, configure its secret here
FEEPAY_WEBHOOK_SECRET = os.environ.get("FEEPAY_WEBHOOK_SECRET", "")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

app = FastAPI(title="FeexPay Webhook", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"]
)


@app.get("/")
def root() -> Dict[str, Any]:
    return {"ok": True, "service": "feexpay-webhook", "version": "1.0.0"}


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "healthy"}


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def verify_signature(raw_body: bytes, provided_sig: Optional[str]) -> None:
    if not FEEPAY_WEBHOOK_SECRET:
        # No configured secret: skip verification
        return
    if not provided_sig:
        raise HTTPException(status_code=401, detail="Missing signature header")
    expected = hmac.new(FEEPAY_WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    if not constant_time_compare(provided_sig, expected):
        raise HTTPException(status_code=401, detail="Invalid signature")


def map_payment_status(provider_status: str) -> str:
    normalized = (provider_status or "").upper()
    if normalized in ("SUCCESS", "SUCCESSFUL", "COMPLETED"):  # FeexPay common values
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
        raise HTTPException(status_code=400, detail="transaction_id or order_number is required")

    status_app = map_payment_status(provider_status or "")

    # Try to update by order_number first
    if order_ref:
        existing = supabase.table("orders").select("id").eq("order_number", order_ref).limit(1).execute()
        if existing.data:
            supabase.table("orders").update({
                "transaction_id": tx_id,
                "payment_reference": order_ref,
                "payment_provider": provider_name,
                "payment_status": provider_status,
                "status": status_app
            }).eq("order_number", order_ref).execute()
            return

    # Otherwise try by transaction_id
    if tx_id:
        existing_tx = supabase.table("orders").select("id").eq("transaction_id", tx_id).limit(1).execute()
        if existing_tx.data:
            supabase.table("orders").update({
                "payment_reference": order_ref,
                "payment_provider": provider_name,
                "payment_status": provider_status,
                "status": status_app
            }).eq("transaction_id", tx_id).execute()
            return

    # If no existing order, insert a minimal record for traceability
    supabase.table("orders").insert({
        "order_number": order_ref,
        "transaction_id": tx_id,
        "payment_reference": order_ref,
        "payment_provider": provider_name,
        "payment_status": provider_status,
        "status": status_app,
        "total_amount": payload.get("amount"),
        "notes": "Created by webhook"
    }).execute()


@app.post("/webhooks/feexpay")
async def feexpay_webhook(request: Request) -> JSONResponse:
    raw = await request.body()
    sig = request.headers.get("X-Feexpay-Signature") or request.headers.get("X-Signature")
    verify_signature(raw, sig)
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


