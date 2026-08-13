#!/usr/bin/env python3
"""Backend leve do MotoJá SP para protótipo.

Uso: python3 server.py
Abra: http://localhost:8080

É uma base de desenvolvimento: não contém autenticação, pagamentos ou
proteções de produção. Os dados ficam em data.json.
"""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from datetime import datetime, timezone
import json
import mimetypes
import re
import threading
import uuid
import hashlib
import hmac
import secrets
import os
import sqlite3
import base64
import math
try:
    from pywebpush import webpush
except ImportError:
    webpush = None
try:
    from payments import create_pix, create_preference, get_payment, PUBLIC_KEY as MP_PUBLIC_KEY
except ImportError:
    from .payments import create_pix, create_preference, get_payment, PUBLIC_KEY as MP_PUBLIC_KEY

ROOT = Path(__file__).resolve().parent
DB = Path(os.getenv("DATA_FILE", str(ROOT / "data.json")))
SQLITE_FILE = Path(os.getenv("SQLITE_FILE", str(ROOT / "motoja.sqlite3")))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(ROOT / "uploads")))
STORAGE = os.getenv("STORAGE", "sqlite").lower()
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "*")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "motoja-admin-demo")
VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_SUBJECT = os.getenv("VAPID_SUBJECT", "mailto:admin@motorja.local")
MP_WEBHOOK_SECRET = os.getenv("MP_WEBHOOK_SECRET", "")
LOCK = threading.Lock()
SESSIONS = {}
PBKDF2_ROUNDS = 180_000
RIDE_RATES = {"moto": 1.0, "priority": 1.25, "economy": 0.84}


def now():
    return datetime.now(timezone.utc).isoformat()


def haversine_km(lat1, lon1, lat2, lon2):
    radius=6371.0; p1=math.radians(float(lat1)); p2=math.radians(float(lat2)); dp=math.radians(float(lat2)-float(lat1)); dl=math.radians(float(lon2)-float(lon1)); a=math.sin(dp/2)**2+math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2; return radius*2*math.atan2(math.sqrt(a),math.sqrt(1-a))


def init_storage():
    if STORAGE == "json":
        return
    SQLITE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(SQLITE_FILE) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS rides (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        conn.commit()


def read_db():
    if STORAGE == "json":
        if not DB.exists(): return {"profiles": [], "rides": []}
        try: return json.loads(DB.read_text(encoding="utf-8"))
        except (ValueError, OSError): return {"profiles": [], "rides": []}
    init_storage()
    with sqlite3.connect(SQLITE_FILE) as conn:
        profiles=[json.loads(row[0]) for row in conn.execute("SELECT payload FROM profiles")]
        rides=[json.loads(row[0]) for row in conn.execute("SELECT payload FROM rides ORDER BY rowid DESC")]
    return {"profiles": profiles, "rides": rides}


def write_db(data):
    if STORAGE == "json":
        temp = DB.with_suffix(".tmp")
        temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(DB)
        return
    init_storage()
    with sqlite3.connect(SQLITE_FILE) as conn:
        conn.execute("DELETE FROM profiles"); conn.execute("DELETE FROM rides")
        conn.executemany("INSERT INTO profiles(id,payload) VALUES (?,?)", [(p["id"], json.dumps(p, ensure_ascii=False)) for p in data["profiles"]])
        conn.executemany("INSERT INTO rides(id,payload) VALUES (?,?)", [(r["id"], json.dumps(r, ensure_ascii=False)) for r in data["rides"]])
        conn.commit()


def public_profile(profile):
    return {k: v for k, v in profile.items() if k not in {"pin_salt", "pin_hash", "cpf", "birth_date", "background_check_consent_at", "face_consent_at"}}


def admin_profile(profile):
    result = public_profile(profile)
    cpf = str(profile.get("cpf", ""))
    result["cpf_masked"] = ("***.***." + cpf[-5:-2] + "-" + cpf[-2:]) if len(cpf) >= 5 else "não informado"
    result["documents"] = [{k: d.get(k) for k in ("id", "kind", "filename", "status", "created_at")} for d in profile.get("documents", [])]
    result["documents_count"] = len(result["documents"])
    result["birth_date"] = profile.get("birth_date")
    result["background_check_status"] = profile.get("background_check_status", "not_required")
    result["face_verification_status"] = profile.get("face_verification_status", "not_required")
    return result


def make_pin_hash(pin, salt_hex):
    return hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), bytes.fromhex(salt_hex), PBKDF2_ROUNDS).hex()


def valid_password(password):
    return bool(re.fullmatch(r"(?=.{8,64}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).*", password))


def token_for(profile_id):
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = profile_id
    return token


def refresh_reputation(data, driver_id):
    if not driver_id: return
    profile = next((p for p in data["profiles"] if p.get("id") == driver_id), None)
    ratings = [int(r["rating"]) for r in data["rides"] if r.get("driver_id") == driver_id and r.get("rating")]
    if not profile: return
    profile["rating_count"] = len(ratings); profile["rating_average"] = round(sum(ratings) / len(ratings), 2) if ratings else 0
    if len(ratings) >= 5 and profile["rating_average"] < 2.5: profile["account_status"] = "suspended"


def notify_profile(data, profile_id, title, message):
    if not profile_id or not webpush or not VAPID_PRIVATE_KEY: return
    profile = next((p for p in data["profiles"] if p.get("id") == profile_id), None)
    for subscription in (profile or {}).get("push_subscriptions", []):
        try: webpush(subscription_info=subscription, data=json.dumps({"title":title,"body":message}), vapid_private_key=VAPID_PRIVATE_KEY, vapid_claims={"sub":VAPID_SUBJECT})
        except Exception: pass


def body(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length else b"{}"
    handler.raw_body = raw
    try:
        result = json.loads(raw.decode("utf-8"))
        return result if isinstance(result, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def is_admin(handler):
    return hmac.compare_digest(handler.headers.get("X-Admin-Token", ""), ADMIN_TOKEN)


def session_profile_id(handler):
    auth = handler.headers.get("Authorization", "")
    return SESSIONS.get(auth[7:]) if auth.startswith("Bearer ") else None


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print("[MotoJá] " + fmt % args)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        super().end_headers()

    def send_json(self, payload, status=200):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            if parsed.path == "/":
                self.path = "/index.html"
            return super().do_GET()
        query = parse_qs(parsed.query)
        with LOCK:
            data = read_db()
            if parsed.path.startswith("/api/admin/"):
                if not is_admin(self): return self.send_json({"error": "Acesso administrativo negado"}, 401)
                doc_admin = re.fullmatch(r"/api/admin/documents/([A-Za-z0-9]+)", parsed.path)
                if doc_admin:
                    found = next(((p, d) for p in data["profiles"] for d in p.get("documents", []) if d.get("id") == doc_admin.group(1)), None)
                    if not found: return self.send_json({"error": "Documento não encontrado"}, 404)
                    path = Path(found[1].get("stored", ""))
                    if not path.exists(): return self.send_json({"error": "Arquivo indisponível"}, 404)
                    raw = path.read_bytes(); self.send_response(200); self.send_header("Content-Type", "application/pdf" if path.suffix == ".pdf" else "image/jpeg"); self.send_header("Content-Length", str(len(raw))); self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN); self.end_headers(); self.wfile.write(raw); return
                if parsed.path == "/api/admin/stats":
                    finished=[r for r in data["rides"] if r.get("status")=="finished"]
                    rated=[r for r in data["rides"] if r.get("rating")]
                    statuses={status:sum(1 for r in data["rides"] if r.get("status")==status) for status in {r.get("status") for r in data["rides"]}}
                    return self.send_json({"profiles":len(data["profiles"]),"rides":len(data["rides"]),"finished":len(finished),"revenue":round(sum(float(r.get("price",0)) for r in finished),2),"average_rating":round(sum(int(r["rating"]) for r in rated)/len(rated),2) if rated else 0,"suspended":sum(1 for p in data["profiles"] if p.get("account_status")=="suspended"),"reports":sum(len(r.get("reports",[])) for r in data["rides"]),"emergencies":sum(len(r.get("emergency_events",[])) for r in data["rides"]),"risk_flags":sum(len(r.get("risk_flags",[])) for r in data["rides"]),"statuses":statuses})
                if parsed.path == "/api/admin/rides": return self.send_json({"rides":data["rides"][:100]})
                if parsed.path == "/api/admin/profiles": return self.send_json({"profiles":[admin_profile(p) for p in data["profiles"]]})
                return self.send_json({"error": "Rota administrativa não encontrada"}, 404)
            if parsed.path == "/api/push/config":
                return self.send_json({"vapid_public_key": VAPID_PUBLIC_KEY, "enabled": bool(VAPID_PUBLIC_KEY and webpush)})
            if parsed.path == "/api/payments/config":
                return self.send_json({"mercado_pago_public_key": MP_PUBLIC_KEY, "enabled": bool(MP_PUBLIC_KEY)})
            if parsed.path == "/api/health":
                return self.send_json({"ok": True, "service": "motoja-sp", "time": now()})
            if parsed.path == "/api/rides":
                rides = data["rides"]
                if query.get("status"):
                    rides = [r for r in rides if r["status"] in query["status"]]
                if query.get("passenger_id"):
                    rides = [r for r in rides if r["passenger_id"] == query["passenger_id"][0]]
                return self.send_json({"rides": rides})
            if parsed.path == "/api/profiles":
                return self.send_json({"profiles": [public_profile(p) for p in data["profiles"]]})
        return self.send_json({"error": "Rota não encontrada"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        payload = body(self)
        if parsed.path == "/api/webhooks/mercadopago":
            if not MP_WEBHOOK_SECRET: return self.send_json({"error": "Webhook não configurado"}, 503)
            signature=self.headers.get("x-signature", ""); parts={}
            for item in signature.split(","):
                if "=" in item:
                    key,value=item.strip().split("=",1); parts[key]=value
            data_id=str((payload.get("data") or {}).get("id") or parse_qs(parsed.query).get("data.id", [""])[0]); request_id=self.headers.get("x-request-id", ""); manifest=f"id:{data_id};request-id:{request_id};ts:{parts.get('ts','')};"; expected=hmac.new(MP_WEBHOOK_SECRET.encode(),manifest.encode(),hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, parts.get("v1", "")): return self.send_json({"error": "Assinatura inválida"}, 401)
            details=get_payment(data_id) or {}; status=details.get("status", "pending")
            with LOCK:
                data=read_db(); ride=next((r for r in data["rides"] if str((r.get("payment") or {}).get("id"))==str(data_id)), None)
                if ride:
                    ride["payment"]["status"]=status; ride["payment"]["external_status_detail"]=details.get("status_detail"); write_db(data)
                    if status=="approved": notify_profile(data,ride.get("passenger_id"),"Pagamento confirmado","Seu pagamento foi aprovado.")
            return self.send_json({"ok": True, "status": status})
        with LOCK:
            data = read_db()
            payment_match = re.fullmatch(r"/api/rides/([A-Za-z0-9]+)/payment", parsed.path)
            if payment_match:
                ride = next((r for r in data["rides"] if r["id"] == payment_match.group(1)), None); method = payload.get("method", "pix")
                if not ride: return self.send_json({"error": "Corrida não encontrada"}, 404)
                if method == "cash": result={"provider":"local","status":"pay_on_trip","method":"cash"}
                elif method == "pix": result=create_pix(ride.get("price",0),f"MotoJá {ride['id']}",payload.get("email"))
                else: result=create_preference(ride.get("price",0),f"MotoJá {ride['id']}")
                tx=(result or {}).get("point_of_interaction",{}).get("transaction_data",{})
                ride["payment"]={"method":method,"provider":(result or {}).get("provider","mercado_pago"),"status":(result or {}).get("status","pending"),"id":(result or {}).get("id"),"qr_code":tx.get("qr_code"),"qr_code_base64":tx.get("qr_code_base64"),"checkout_url":(result or {}).get("init_point")}
                write_db(data); return self.send_json({"payment":ride["payment"],"public_key":MP_PUBLIC_KEY})
            push_match = re.fullmatch(r"/api/profiles/([A-Za-z0-9]+)/push-subscription", parsed.path)
            if push_match:
                profile_id = session_profile_id(self)
                if profile_id != push_match.group(1): return self.send_json({"error": "Sessão inválida"}, 401)
                profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
                subscription = payload.get("subscription", payload)
                if not profile or not isinstance(subscription, dict) or not subscription.get("endpoint"): return self.send_json({"error": "Assinatura inválida"}, 400)
                profile.setdefault("push_subscriptions", [])
                profile["push_subscriptions"] = [s for s in profile["push_subscriptions"] if s.get("endpoint") != subscription.get("endpoint")]
                profile["push_subscriptions"].append(subscription); write_db(data)
                return self.send_json({"ok": True}, 201)
            doc_match = re.fullmatch(r"/api/profiles/([A-Za-z0-9]+)/documents", parsed.path)
            if doc_match:
                profile_id = session_profile_id(self)
                if profile_id != doc_match.group(1): return self.send_json({"error": "Sessão inválida"}, 401)
                profile = next((p for p in data["profiles"] if p["id"] == profile_id), None)
                raw_text = str(payload.get("content_base64", "")); filename = Path(str(payload.get("filename", "document"))).name; kind = str(payload.get("kind", "document"))
                if not profile or not raw_text or len(raw_text) > 7_000_000: return self.send_json({"error": "Documento ausente ou muito grande"}, 400)
                try: raw = base64.b64decode(raw_text, validate=True)
                except (ValueError, base64.binascii.Error): return self.send_json({"error": "Arquivo inválido"}, 400)
                if len(raw) > 5_000_000: return self.send_json({"error": "Cada documento deve ter no máximo 5 MB"}, 400)
                suffix = ".pdf" if filename.lower().endswith(".pdf") else ".jpg"
                UPLOAD_DIR.mkdir(parents=True, exist_ok=True); doc_id = uuid.uuid4().hex[:12]; stored = UPLOAD_DIR / f"{doc_id}{suffix}"; stored.write_bytes(raw)
                doc = {"id": doc_id, "kind": kind[:40], "filename": filename[:120], "stored": str(stored), "status": "pending", "created_at": now()}
                profile.setdefault("documents", []).append(doc); write_db(data)
                return self.send_json({k: doc[k] for k in ("id", "kind", "filename", "status", "created_at")}, 201)
            if parsed.path.startswith("/api/admin/"):
                if not is_admin(self): return self.send_json({"error": "Acesso administrativo negado"}, 401)
                match_admin = re.fullmatch(r"/api/admin/profiles/([A-Za-z0-9]+)/verification", parsed.path)
                if match_admin:
                    profile = next((p for p in data["profiles"] if p["id"] == match_admin.group(1)), None)
                    status = payload.get("status")
                    if not profile or status not in {"approved", "rejected", "pending"}: return self.send_json({"error": "Perfil ou status inválido"}, 400)
                    if status == "approved" and len(profile.get("documents", [])) < 5: return self.send_json({"error": "Envie RG, CNH, carteira, foto e selfie antes de aprovar"}, 400)
                    if status == "approved" and profile.get("background_check_status") not in {"pending_review", "approved"}: return self.send_json({"error": "A verificação de antecedentes precisa estar autorizada"}, 400)
                    if status == "approved" and profile.get("face_verification_status") not in {"pending_review", "approved"}: return self.send_json({"error": "O reconhecimento facial precisa estar autorizado"}, 400)
                    profile["verification_status"] = status; profile["verification_note"] = str(payload.get("note", ""))[:300]; profile["background_check_status"] = "approved" if status == "approved" else ("rejected" if status == "rejected" else profile.get("background_check_status", "pending_review")); profile["face_verification_status"] = "approved" if status == "approved" else ("rejected" if status == "rejected" else profile.get("face_verification_status", "pending_review")); profile["updated_at"] = now(); write_db(data)
                    return self.send_json(admin_profile(profile))
                match_status = re.fullmatch(r"/api/admin/profiles/([A-Za-z0-9]+)/status", parsed.path)
                if match_status:
                    profile = next((p for p in data["profiles"] if p["id"] == match_status.group(1)), None); status = payload.get("status")
                    if not profile or status not in {"active", "suspended"}: return self.send_json({"error": "Perfil ou status inválido"}, 400)
                    profile["account_status"] = status; profile["updated_at"] = now(); write_db(data); return self.send_json(admin_profile(profile))
                return self.send_json({"error": "Rota administrativa não encontrada"}, 404)
            if parsed.path == "/api/auth/register":
                name, phone = str(payload.get("name", "")).strip(), str(payload.get("phone", "")).strip()
                pin = str(payload.get("password", payload.get("pin", ""))).strip()
                role = payload.get("role", "passenger")
                email = str(payload.get("email", "")).strip().lower()
                cpf = re.sub(r"\D", "", str(payload.get("cpf", "")))
                birth_date = str(payload.get("birth_date", "")).strip()
                background_consent = bool(payload.get("background_check_consent"))
                face_consent = bool(payload.get("face_consent"))
                plate = re.sub(r"[^A-Za-z0-9]", "", str(payload.get("plate", ""))).upper()
                if not name or not phone or not valid_password(pin):
                    return self.send_json({"error": "Nome, celular e senha forte de 8 caracteres são obrigatórios"}, 400)
                if role == "driver" and (len(cpf) != 11 or len(plate) < 7 or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", birth_date) or not background_consent or not face_consent):
                    return self.send_json({"error": "Motorista precisa informar CPF, placa, data, autorizar antecedentes e reconhecimento facial"}, 400)
                if role == "passenger" and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                    return self.send_json({"error": "Passageiro precisa informar um email válido"}, 400)
                if any(p.get("phone") == phone for p in data["profiles"]):
                    return self.send_json({"error": "Celular já cadastrado"}, 409)
                salt = secrets.token_hex(16)
                profile = {"id": uuid.uuid4().hex[:12], "name": name, "phone": phone, "email": email or None, "role": role, "cpf": cpf or None, "birth_date": birth_date or None, "plate": plate or None, "background_check_status": "pending_review" if role == "driver" else "not_required", "background_check_consent_at": now() if role == "driver" and background_consent else None, "face_verification_status": "pending_review" if role == "driver" else "not_required", "face_consent_at": now() if role == "driver" and face_consent else None, "verification_status": "pending" if role == "driver" else "not_required", "account_status": "active", "reports_count": 0, "pin_salt": salt, "pin_hash": make_pin_hash(pin, salt), "created_at": now()}
                data["profiles"].append(profile); write_db(data)
                return self.send_json({"token": token_for(profile["id"]), "profile": public_profile(profile)}, 201)
            if parsed.path == "/api/auth/login":
                phone, pin = str(payload.get("phone", "")).strip(), str(payload.get("password", payload.get("pin", ""))).strip()
                profile = next((p for p in data["profiles"] if p.get("phone") == phone), None)
                if not profile or not valid_password(pin) or not hmac.compare_digest(profile.get("pin_hash", ""), make_pin_hash(pin, profile.get("pin_salt", ""))):
                    return self.send_json({"error": "Celular ou senha inválida"}, 401)
                profile.setdefault("verification_status", "not_required" if profile.get("role") != "driver" else "pending")
                return self.send_json({"token": token_for(profile["id"]), "profile": public_profile(profile)})
            if parsed.path == "/api/auth/logout":
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Bearer "): SESSIONS.pop(auth[7:], None)
                return self.send_json({"ok": True})
            if parsed.path == "/api/profiles":
                if not payload.get("name") or not payload.get("phone"):
                    return self.send_json({"error": "Nome e celular são obrigatórios"}, 400)
                profile = next((p for p in data["profiles"] if p["phone"] == payload["phone"]), None)
                if profile:
                    profile.update({"name": payload["name"], "role": payload.get("role", "passenger"), "updated_at": now()})
                else:
                    profile = {"id": uuid.uuid4().hex[:12], "name": payload["name"], "phone": payload["phone"], "role": payload.get("role", "passenger"), "created_at": now()}
                    data["profiles"].append(profile)
                write_db(data)
                return self.send_json(public_profile(profile), 201)
            if parsed.path == "/api/rides":
                required = ("passenger_id", "origin", "destination", "distance")
                if any(not payload.get(key) for key in required):
                    return self.send_json({"error": "Dados da corrida incompletos"}, 400)
                distance = float(payload["distance"]); ride_type = payload.get("ride_type", "moto"); rate = RIDE_RATES.get(ride_type, 1.0)
                passenger = next((p for p in data["profiles"] if p.get("id") == payload["passenger_id"]), None) or {}
                passenger_rating = float(passenger.get("rating_average") or 0)
                passenger_rating_count = int(passenger.get("rating_count") or 0)
                ride = {"id": uuid.uuid4().hex[:12], "passenger_id": payload["passenger_id"], "passenger_name": passenger.get("name", "Passageiro"), "passenger_rating": passenger_rating, "passenger_rating_count": passenger_rating_count, "driver_id": None, "origin": payload["origin"], "destination": payload["destination"], "distance": distance, "ride_type": ride_type, "price": round(max(8, (6.5 + distance * 1.56) * rate), 2), "eta_minutes": max(7, round(distance * 3)), "payment_method": payload.get("payment_method", "pix"), "rating": None, "status": "searching", "created_at": now(), "updated_at": now()}
                data["rides"].insert(0, ride)
                write_db(data)
                return self.send_json(ride, 201)
            match = re.fullmatch(r"/api/rides/([A-Za-z0-9]+)/([a-z]+)", parsed.path)
            if match:
                ride_id, action = match.groups()
                ride = next((r for r in data["rides"] if r["id"] == ride_id), None)
                if not ride:
                    return self.send_json({"error": "Corrida não encontrada"}, 404)
                if action == "accept":
                    driver_id = payload.get("driver_id", "demo-driver"); driver = next((p for p in data["profiles"] if p.get("id") == driver_id), None)
                    if driver and (driver.get("verification_status") != "approved" or driver.get("account_status", "active") in {"suspended", "review"}): return self.send_json({"error": "Motociclista não está habilitado"}, 403)
                    ride["status"] = "accepted"; ride["driver_id"] = driver_id; ride["driver_lat"] = payload.get("lat"); ride["driver_lng"] = payload.get("lng"); ride["location_at"] = now(); ride["updated_at"] = now(); notify_profile(data, ride.get("passenger_id"), "Motociclista encontrado", "Seu motorista está a caminho.")
                elif action == "location":
                    if ride["status"] != "accepted": return self.send_json({"error": "Corrida ainda não foi aceita"}, 409)
                    lat, lng, stamp = payload.get("lat"), payload.get("lng"), now()
                    try:
                        previous = datetime.fromisoformat(ride["location_at"]); elapsed=max((datetime.fromisoformat(stamp)-previous).total_seconds(), 1); km=haversine_km(ride["driver_lat"], ride["driver_lng"], lat, lng); speed=km/elapsed*3600
                    except (KeyError, TypeError, ValueError): speed=0
                    if speed > 140:
                        ride.setdefault("risk_flags", []).append({"type":"high_speed", "speed_kmh":round(speed,1), "created_at":stamp})
                        driver = next((p for p in data["profiles"] if p.get("id") == ride.get("driver_id")), None)
                        if driver: driver["account_status"] = "review"
                    ride["driver_lat"] = lat; ride["driver_lng"] = lng; ride["location_at"] = stamp; ride["updated_at"] = stamp
                elif action == "rating":
                    try: rating = int(payload.get("rating"))
                    except (TypeError, ValueError): rating = 0
                    if rating < 1 or rating > 5: return self.send_json({"error": "Nota deve estar entre 1 e 5"}, 400)
                    ride["rating"] = rating; ride["updated_at"] = now(); refresh_reputation(data, ride.get("driver_id"))
                elif action == "emergency":
                    ride.setdefault("emergency_events", []).append({"type": payload.get("type", "unknown"), "created_at": now()}); ride["risk_status"] = "emergency"
                elif action == "report":
                    reason = str(payload.get("reason", "")).strip()
                    if len(reason) < 5: return self.send_json({"error": "Descreva o problema"}, 400)
                    ride.setdefault("reports", []).append({"id": uuid.uuid4().hex[:12], "reason": reason[:500], "created_at": now()})
                    driver = next((p for p in data["profiles"] if p.get("id") == ride.get("driver_id")), None)
                    if driver:
                        driver["reports_count"] = int(driver.get("reports_count", 0)) + 1
                        if driver["reports_count"] >= 3: driver["account_status"] = "suspended"
                elif action == "cancel":
                    ride["status"] = "cancelled"; ride["updated_at"] = now()
                elif action == "finish":
                    ride["status"] = "finished"; ride["updated_at"] = now(); notify_profile(data, ride.get("passenger_id"), "Corrida finalizada", "Sua corrida foi finalizada.")
                else:
                    return self.send_json({"error": "Ação não encontrada"}, 404)
                write_db(data)
                return self.send_json(ride)
        return self.send_json({"error": "Rota não encontrada"}, 404)


if __name__ == "__main__":
    init_storage()
    port = int(os.getenv("PORT", "8080"))
    print(f"MotoJá SP em http://localhost:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
