import os
import hmac
import json
import re
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


# -------------------------
# Identification de la commande
# -------------------------
# Le webhook FeexPay ne transmet PAS de champ `order_number` : ce nom
# n'apparaît nulle part dans la documentation de l'API v2. Le payload réel
# documenté est :
#
#   {
#     "reference": "1e636dff-…",     <- identifiant FeexPay (UUID)
#     "order_id":   "1e636dff-…",     <- id interne FeexPay, PAS le nôtre
#     "status": "SUCCESSFUL",
#     "callback_info": "",            <- chaîne vide, ou objet selon l'envoi
#     "phoneNumber": "2290190877433",
#     "reseau": "MTN CI", …
#   }
#
# Seul `callback_info` transporte notre donnée : le SDK y place
# order_number lors de la création du paiement. Selon la doc, il est renvoyé
# sous forme d'objet quand on en envoie un, mais reste une chaîne (vide) sinon.
# D'où les deux formes acceptées ci-dessous.
#
# En repli, `custom_id` (que nous remplissons avec EP_<orderNumber>_<bcp>)
# permet de récupérer le numéro de commande.
# custom_id est construit par le front sous la forme
# `EP_<orderNumber>_<timestamp><2 majuscules>` (cf. generatePaymentReference).
# Le timestamp est `Date.now().slice(-6)` : c'est bien 6 chiffres, mais on ne
# peut pas s'y fier pour valider — une référence tronquée ou un ancien format
# doit rester lisible. On exige donc un suffixe alphanumérique d'au moins 4
# caractères, ce qui exclut les simples libellés commençant par 'EP_'.
#
# Les numéros de commande contiennent un tiret ('CMD-RJOWEFM') : la classe est
# large et non gloutonne pour s'arrêter au dernier séparateur valide.
_ORDER_REF_RE = re.compile(r"^EP_(.+?)_[A-Z0-9]{6,}$")


def _as_dict(value: Any) -> Dict[str, Any]:
    """Normalise callback_info en dictionnaire.

    FeexPay renvoie soit un objet JSON, soit une chaîne (vide le plus
    souvent, mais elle peut contenir du JSON sérialisé).
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}


def extract_order_ref(payload: Dict[str, Any]) -> Optional[str]:
    """Retrouve le numéro de commande (ex. 'CMD-RJOWEFM') dans la notification.

    Ordre de recherche : callback_info.order_number, puis custom_id, puis
    callback_info.order / id. Ne retourne None que si rien ne correspond — cas
    qui doit empêcher toute écriture en base (cf. upsert_order).
    """
    info = _as_dict(payload.get("callback_info"))

    for key in ("order_number", "orderNumber", "order", "id"):
        value = info.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    # custom_id a été envoyé sous le nom "customId" par le SDK.
    for key in ("custom_id", "customId"):
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            continue

        value = value.strip()
        match = _ORDER_REF_RE.match(value)
        if match:
            return match.group(1)

        # Une valeur commençant par 'EP_' mais ne respectant pas le format
        # n'est pas un numéro de commande exploitable : on l'ignore plutôt
        # que de la renvoyer telle quelle, ce qui polluerait la base.
        if not value.upper().startswith("EP_"):
            return value

    return None


def upsert_order(payload: Dict[str, Any]) -> None:
    tx_id = payload.get("transaction_id") or payload.get("reference")
    order_ref = extract_order_ref(payload)
    provider_status = payload.get("status") or payload.get("payment_status")
    provider_name = payload.get("payment_provider") or "feexpay"

    # Sans identifiant de commande, on ne touche pas à la base. FeeexPay
    # émet plusieurs notifications par transaction : insérer ici créerait des
    # lignes fantômes (sans id ni date, donc déjà malformées) à chaque
    # notification d'une commande qu'on n'arrive pas à rattacher.
    if not order_ref:
        print(
            f"[feexpay] notification sans identifiant de commande, ignorée "
            f"(reference={tx_id}, callback_info={payload.get('callback_info')!r})",
            flush=True,
        )
        return

    status_app = map_payment_status(provider_status or "")

    # 1️⃣ Update par order_number
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
        print(f"[feexpay] commande {order_ref} -> {status_app}", flush=True)
        return

    # 2️⃣ Update par transaction_id (une commande déjà rattachée à cette
    # transaction, mais dont le numéro a changé côté base).
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
                "order_number": order_ref,
                "payment_reference": order_ref,
                "payment_provider": provider_name,
                "payment_status": provider_status,
                "status": status_app,
            }).eq("transaction_id", tx_id).execute()
            print(
                f"[feexpay] commande rattachée par transaction {tx_id} "
                f"-> {order_ref} ({status_app})",
                flush=True,
            )
            return

    # 3️⃣ Commande inconnue : on ne crée PAS de ligne partielle. Une commande
    # est toujours créée par le site au moment du checkout ; une notification
    # qui ne la retrouve pas signifie que le numéro de commande envoyé n'est
    # pas lebon (format changed, commande supprimée…). Créer une ligne
    # minimaliste masquerait le problème et fausserait les statistiques.
    print(
        f"[feexpay] aucune commande ne correspond à {order_ref} "
        f"(reference={tx_id}) : notification ignorée",
        flush=True,
    )


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
