# FeexPay Webhook (FastAPI on Railway)

## Deploy on Railway

1. Create a new Railway project → Deploy from GitHub (this repo) and set the root to `webhook-python/`.
2. Set Environment Variables:
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `FEEPAY_WEBHOOK_SECRET` (optional if signature is provided)
3. Railway auto-detects `Procfile`, start command:
   
   web: uvicorn main:app --host 0.0.0.0 --port ${PORT}
   
4. After deploy, note your public URL, e.g. `https://your-app.up.railway.app`.

## Configure FeexPay Webhook

Set the webhook URL in FeexPay dashboard to:

https://your-app.up.railway.app/webhooks/feexpay

## Payload Handling

- Accepts JSON body from FeexPay containing at least:
  - `transaction_id` or `reference`
  - `status` (e.g., SUCCESSFUL | FAILED | PENDING)
  - optional `order_number`, `amount`
- Upserts into Supabase `orders` table by `order_number` or `transaction_id`.
- Maps provider status → app status: SUCCESSFUL→confirmed, FAILED→failed, otherwise pending.

## Local Run

python -m venv .venv
. .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
export SUPABASE_URL=...
export SUPABASE_SERVICE_ROLE_KEY=...
uvicorn main:app --reload

Then POST to `http://127.0.0.1:8000/webhooks/feexpay` with a sample payload:

{ "transaction_id": "tx_123", "order_number": "EP123ABC", "status": "SUCCESSFUL", "amount": 15000 }


