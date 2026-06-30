import os
import time
import hmac
import base64
import hashlib
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response, Cookie
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config, ad, lark, scheduler

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("app")

app = FastAPI(title="Bearhouse and Sunsu — ศูนย์รหัสผ่าน")
STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")

# ----- Session (cookie ลงนามด้วย HMAC + มี timeout) -----
SESSION_SECRET = os.getenv("SESSION_SECRET") or base64.b64encode(os.urandom(32)).decode()
SESSION_TTL = int(os.getenv("SESSION_TIMEOUT_MIN", "30")) * 60
COOKIE = "pwdsession"


def _sign(payload: str) -> str:
    return hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _make_token(username: str) -> str:
    payload = f"{username}|{int(time.time()) + SESSION_TTL}"
    b = base64.urlsafe_b64encode(payload.encode()).decode()
    return f"{b}.{_sign(payload)}"


def _parse_token(token: str):
    try:
        b, sig = token.split(".", 1)
        payload = base64.urlsafe_b64decode(b.encode()).decode()
        if not hmac.compare_digest(sig, _sign(payload)):
            return None
        username, exp = payload.split("|", 1)
        if int(exp) < int(time.time()):
            return None
        return username
    except Exception:
        return None


def _set_session(resp: Response, username: str):
    resp.set_cookie(COOKIE, _make_token(username), max_age=SESSION_TTL,
                    httponly=True, samesite="lax", path="/")


def _require_user(session: str):
    user = _parse_token(session) if session else None
    if not user:
        raise HTTPException(401, "เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่")
    return user


_sch = None


@app.on_event("startup")
def _startup():
    global _sch
    try:
        _sch = scheduler.start()
    except Exception as e:  # noqa
        log.error("เริ่มตัวตั้งเวลาไม่ได้: %s", e)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True, "ad": config.AD_ENABLED, "lark": config.LARK_ENABLED}


class LoginIn(BaseModel):
    username: str
    password: str


class ChangeIn(BaseModel):
    current: str
    new_password: str


def _status_or_500(username: str):
    try:
        return ad.get_status(username)
    except LookupError:
        raise HTTPException(404, "ไม่พบบัญชีผู้ใช้")
    except Exception as e:  # noqa
        raise HTTPException(500, f"อ่านสถานะจาก AD ไม่ได้: {e}")


@app.post("/api/login")
def login(body: LoginIn, response: Response):
    if not config.AD_ENABLED:
        raise HTTPException(503, "ยังไม่ได้ตั้งค่าเชื่อม AD")
    if not ad.verify_password(body.username, body.password):
        raise HTTPException(401, "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง")
    data = _status_or_500(body.username)
    try:
        data["is_admin"] = config.ADMIN_ENABLED and ad.is_admin(body.username)
    except Exception:  # noqa
        data["is_admin"] = False
    _set_session(response, body.username)
    return data


@app.get("/api/me")
def me(response: Response, pwdsession: str = Cookie(None)):
    user = _require_user(pwdsession)
    data = _status_or_500(user)
    try:
        data["is_admin"] = config.ADMIN_ENABLED and ad.is_admin(user)
    except Exception:  # noqa
        data["is_admin"] = False
    _set_session(response, user)   # sliding: ต่ออายุทุกครั้งที่ใช้งาน
    return data


@app.get("/api/status")
def status(response: Response, pwdsession: str = Cookie(None)):
    user = _require_user(pwdsession)
    data = _status_or_500(user)
    _set_session(response, user)
    return data


@app.post("/api/change-password")
def change_password(body: ChangeIn, response: Response, pwdsession: str = Cookie(None)):
    user = _require_user(pwdsession)
    if not config.AD_ENABLED:
        raise HTTPException(503, "ยังไม่ได้ตั้งค่าเชื่อม AD")
    try:
        ad.change_password(user, body.current, body.new_password)
    except PermissionError as e:
        raise HTTPException(401, str(e))
    except Exception as e:  # noqa
        raise HTTPException(400, f"เปลี่ยนรหัสไม่สำเร็จ: {e}")
    _set_session(response, user)
    return {"ok": True}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


# ═══════════════════════════════════════════════════════════════════════════
#  ADMIN CONSOLE
# ═══════════════════════════════════════════════════════════════════════════

def _require_admin(session: str) -> str:
    user = _require_user(session)
    if not config.ADMIN_ENABLED:
        raise HTTPException(503, "ยังไม่ได้เปิดใช้งานโหมดผู้ดูแล (ตั้งค่า ADMIN_USERS หรือ ADMIN_GROUP)")
    try:
        ok = ad.is_admin(user)
    except Exception as e:  # noqa
        raise HTTPException(500, f"ตรวจสิทธิ์ผู้ดูแลไม่ได้: {e}")
    if not ok:
        raise HTTPException(403, "บัญชีนี้ไม่มีสิทธิ์เข้าหน้าผู้ดูแลระบบ")
    return user


@app.get("/admin")
def admin_page():
    return FileResponse(STATIC / "admin.html")


@app.get("/api/admin/whoami")
def admin_whoami(response: Response, pwdsession: str = Cookie(None)):
    user = _require_admin(pwdsession)
    _set_session(response, user)
    return {"username": user, "is_admin": True}


@app.get("/api/admin/users")
def admin_users(response: Response, q: str = "", limit: int = 500,
                pwdsession: str = Cookie(None)):
    _require_admin(pwdsession)
    try:
        users = ad.list_users(q.strip(), min(max(limit, 1), 1000))
    except Exception as e:  # noqa
        raise HTTPException(500, f"ดึงรายชื่อผู้ใช้จาก AD ไม่ได้: {e}")
    return {"users": users, "stats": ad.summarize(users)}


@app.get("/api/admin/ous")
def admin_ous(pwdsession: str = Cookie(None)):
    _require_admin(pwdsession)
    try:
        return {"ous": ad.list_ous(),
                "default_ou": config.ADMIN_DEFAULT_OU or config.AD_USER_OU}
    except Exception as e:  # noqa
        raise HTTPException(500, f"ดึงรายการ OU ไม่ได้: {e}")


class AdminActionIn(BaseModel):
    username: str


class AdminResetIn(BaseModel):
    username: str
    new_password: str
    must_change: bool = True


class AdminEnableIn(BaseModel):
    username: str
    enabled: bool


class AdminCreateIn(BaseModel):
    first: str
    last: str
    username: str
    password: str
    ou: str
    mail: str | None = ""
    department: str | None = ""
    title: str | None = ""
    must_change: bool = True
    enabled: bool = True


def _admin_do(fn, *args):
    try:
        fn(*args)
    except LookupError:
        raise HTTPException(404, "ไม่พบบัญชีผู้ใช้")
    except Exception as e:  # noqa
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.post("/api/admin/unlock")
def admin_unlock(body: AdminActionIn, pwdsession: str = Cookie(None)):
    _require_admin(pwdsession)
    return _admin_do(ad.admin_unlock, body.username)


@app.post("/api/admin/enable")
def admin_enable(body: AdminEnableIn, pwdsession: str = Cookie(None)):
    _require_admin(pwdsession)
    return _admin_do(ad.admin_set_enabled, body.username, body.enabled)


@app.post("/api/admin/force-change")
def admin_force_change(body: AdminActionIn, pwdsession: str = Cookie(None)):
    _require_admin(pwdsession)
    return _admin_do(ad.admin_force_change, body.username)


@app.post("/api/admin/reset-password")
def admin_reset(body: AdminResetIn, pwdsession: str = Cookie(None)):
    _require_admin(pwdsession)
    return _admin_do(ad.admin_reset_password, body.username,
                     body.new_password, body.must_change)


@app.post("/api/admin/create-user")
def admin_create(body: AdminCreateIn, pwdsession: str = Cookie(None)):
    _require_admin(pwdsession)
    try:
        info = ad.admin_create_user(
            body.first, body.last, body.username, body.password, body.ou,
            body.mail or "", body.department or "", body.title or "",
            body.must_change, body.enabled)
        return {"ok": True, **info}
    except Exception as e:  # noqa
        raise HTTPException(400, f"สร้างบัญชีไม่สำเร็จ: {e}")


@app.post("/api/admin/notify")
def admin_notify(body: AdminActionIn, pwdsession: str = Cookie(None)):
    _require_admin(pwdsession)
    if not config.LARK_ENABLED:
        raise HTTPException(503, "ยังไม่ได้ตั้งค่า Lark")
    try:
        st = ad.get_status(body.username)
    except LookupError:
        raise HTTPException(404, "ไม่พบบัญชีผู้ใช้")
    email = st.get("mail")
    if not email:
        raise HTTPException(400, "บัญชีนี้ไม่มีอีเมลใน AD")
    oid = lark.open_id_by_email(email)
    if not oid:
        raise HTTPException(404, f"ไม่พบบัญชี Lark ตามอีเมล {email}")
    days = st.get("days_left", 0)
    lark.send_expiry_card(oid, st.get("display_name") or body.username,
                          days if days < 9999 else 0, st.get("expiry_date", "-"))
    return {"ok": True, "email": email}


class TestNotifyIn(BaseModel):
    email: str | None = None


@app.post("/api/notify/test")
def notify_test(response: Response, pwdsession: str = Cookie(None),
                body: TestNotifyIn | None = None):
    user = _require_user(pwdsession)
    if not config.LARK_ENABLED:
        raise HTTPException(503, "ยังไม่ได้ตั้งค่า Lark")
    st = _status_or_500(user)
    email = body.email if (body and body.email) else st.get("mail")
    if not email:
        raise HTTPException(400, "บัญชีนี้ไม่มีอีเมลใน AD")
    oid = lark.open_id_by_email(email)
    if not oid:
        raise HTTPException(404, f"ไม่พบบัญชี Lark ตามอีเมล {email} — ตรวจ Availability ของแอป "
                                 f"และอีเมลใน Lark ให้ตรงกับ AD")
    days = st.get("days_left", 0)
    lark.send_expiry_card(oid, st.get("display_name") or user,
                          days if days < 9999 else 0, st.get("expiry_date", "-"))
    _set_session(response, user)
    return {"ok": True, "email": email, "open_id": oid}


@app.post("/api/notify/run")
def notify_run():
    return scheduler.scan_and_notify()
