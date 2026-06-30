"""เชื่อม Active Directory ผ่าน LDAPS: ตรวจรหัส / อ่านวันหมดอายุ / เปลี่ยนรหัส"""
import ssl
from datetime import datetime, timezone, timedelta

from ldap3 import Server, Connection, Tls, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException

from . import config

import logging
log = logging.getLogger("ad")

EPOCH_AS_FILETIME = 116444736000000000  # 1601->1970 ใน FILETIME (100ns ticks)
NEVER = (0, 9223372036854775807)
BKK = timezone(timedelta(hours=7))  # เวลาไทย


def _tls():
    validate = ssl.CERT_REQUIRED if config.AD_TLS_VALIDATE == "required" else ssl.CERT_NONE
    ca = config.AD_CA_CERT if config.AD_TLS_VALIDATE == "required" else None
    return Tls(validate=validate, ca_certs_file=ca, version=ssl.PROTOCOL_TLS_CLIENT)


def _server():
    return Server(config.AD_HOST, port=config.AD_PORT, use_ssl=config.AD_USE_SSL,
                  tls=_tls(), get_info=ALL)


def _service_conn():
    return Connection(_server(), user=config.AD_BIND_USER,
                      password=config.AD_BIND_PASSWORD, auto_bind=True)


def _filetime_to_dt(ft):
    if ft is None:
        return None
    if isinstance(ft, datetime):
        return ft if ft.tzinfo else ft.replace(tzinfo=timezone.utc)
    try:
        ft = int(ft)
    except (TypeError, ValueError):
        return None
    if ft in NEVER:
        return None
    secs = (ft - EPOCH_AS_FILETIME) / 10_000_000
    return datetime.fromtimestamp(secs, tz=timezone.utc)


def verify_password(username: str, password: str) -> bool:
    """ลอง bind ด้วยรหัสของผู้ใช้เอง"""
    if not password:
        return False
    if "@" in username or "\\" in username:
        upn = username
    else:
        upn = f"{username}@{config.AD_UPN_SUFFIX}"
    try:
        conn = Connection(_server(), user=upn, password=password)
        ok = conn.bind()
        if not ok:
            log.warning("bind ล้มเหลว user=%s result=%s", upn, conn.result)
        else:
            conn.unbind()
        return bool(ok)
    except LDAPException as e:
        log.error("bind error user=%s: %s", upn, e)
        return False


def _find_user(conn, username: str):
    conn.search(config.AD_BASE_DN, f"(sAMAccountName={username})", SUBTREE,
                attributes=["distinguishedName", "displayName", "mail",
                            "department", "title",
                            "msDS-UserPasswordExpiryTimeComputed",
                            "pwdLastSet", "lastLogonTimestamp",
                            "userAccountControl"])
    return conn.entries[0] if conn.entries else None


def get_status(username: str) -> dict:
    """อ่านสถานะรหัสผ่านของผู้ใช้คนหนึ่ง"""
    conn = _service_conn()
    e = _find_user(conn, username)
    conn.unbind()
    if e is None:
        raise LookupError("user not found")
    now = datetime.now(timezone.utc)
    exp = _filetime_to_dt(e["msDS-UserPasswordExpiryTimeComputed"].value)
    changed = _filetime_to_dt(e["pwdLastSet"].value)
    logon = _filetime_to_dt(e["lastLogonTimestamp"].value)
    days = (exp - now).days if exp else None
    age = (now - changed).days if changed else None
    cycle = (exp - changed).days if (exp and changed) else None
    try:
        enabled = not (int(e["userAccountControl"].value) & 0x2)
    except Exception:
        enabled = True
    return {
        "username": username,
        "display_name": str(e["displayName"].value or username),
        "mail": str(e["mail"].value or ""),
        "department": str(e["department"].value or ""),
        "title": str(e["title"].value or ""),
        "expiry": exp.isoformat() if exp else None,
        "expiry_date": exp.strftime("%-d/%-m/%Y") if exp else "ไม่หมดอายุ",
        "days_left": days if days is not None else 9999,
        "changed_date": changed.astimezone(BKK).strftime("%-d/%-m/%Y") if changed else "-",
        "password_age_days": age,
        "cycle_days": cycle,
        "last_logon": logon.astimezone(BKK).strftime("%-d/%-m/%Y %H:%M") if logon else "-",
        "account_enabled": enabled,
    }


def change_password(username: str, current: str, new_password: str):
    """เปลี่ยนรหัสผ่านผ่าน LDAPS (ต้องรู้รหัสเดิม)"""
    if not verify_password(username, current):
        raise PermissionError("รหัสผ่านปัจจุบันไม่ถูกต้อง")
    conn = _service_conn()
    try:
        e = _find_user(conn, username)
        if e is None:
            raise LookupError("user not found")
        dn = str(e["distinguishedName"].value)
        ok = conn.extend.microsoft.modify_password(dn, new_password, current)
        if not ok:
            raise RuntimeError(conn.result.get("description", "เปลี่ยนรหัสไม่สำเร็จ"))
    finally:
        conn.unbind()


def list_expiring(days_set):
    """คืนรายชื่อผู้ใช้ที่วันเหลือตรงกับ days_set (สำหรับงานแจ้งเตือน)"""
    conn = _service_conn()
    out = []
    try:
        conn.search(config.AD_USER_OU,
                    "(&(objectClass=user)(objectCategory=person)(mail=*))",
                    SUBTREE,
                    attributes=["sAMAccountName", "displayName", "mail",
                                "msDS-UserPasswordExpiryTimeComputed"])
        now = datetime.now(timezone.utc)
        for e in conn.entries:
            exp = _filetime_to_dt(e["msDS-UserPasswordExpiryTimeComputed"].value)
            if exp is None:
                continue
            days = (exp - now).days
            if days in days_set:
                out.append({
                    "username": str(e["sAMAccountName"].value),
                    "display_name": str(e["displayName"].value or ""),
                    "mail": str(e["mail"].value or ""),
                    "days_left": days,
                    "expiry_date": exp.strftime("%-d/%-m/%Y"),
                })
    finally:
        conn.unbind()
    return out


# ═══════════════════════════════════════════════════════════════════════════
#  ADMIN — จัดการผู้ใช้ทั้งโดเมน (ต้องมอบสิทธิ์ Reset Password / Account ที่ OU)
# ═══════════════════════════════════════════════════════════════════════════

from ldap3 import MODIFY_REPLACE, MODIFY_ADD

# userAccountControl bit flags
UAC_DISABLED        = 0x0002
UAC_DONT_EXPIRE_PWD = 0x10000
UAC_NORMAL_ACCOUNT  = 0x0200
# msDS-User-Account-Control-Computed bit flags
UACC_LOCKOUT        = 0x0010
UACC_PWD_EXPIRED    = 0x800000

_ADMIN_ATTRS = [
    "sAMAccountName", "distinguishedName", "displayName", "givenName", "sn",
    "mail", "department", "title",
    "userAccountControl", "msDS-User-Account-Control-Computed",
    "msDS-UserPasswordExpiryTimeComputed", "pwdLastSet",
    "lastLogonTimestamp", "lockoutTime", "whenCreated",
]


def _ou_of(dn: str) -> str:
    """ดึง path OU แบบอ่านง่ายจาก distinguishedName"""
    if not dn:
        return ""
    parts = [p for p in dn.split(",") if p.upper().startswith("OU=")]
    return " / ".join(p.split("=", 1)[1] for p in reversed(parts)) or "(Root)"


def _entry_to_user(e) -> dict:
    now = datetime.now(timezone.utc)
    dn = str(e["distinguishedName"].value or "")
    try:
        uac = int(e["userAccountControl"].value or 0)
    except (TypeError, ValueError):
        uac = 0
    try:
        uacc = int(e["msDS-User-Account-Control-Computed"].value or 0)
    except (TypeError, ValueError):
        uacc = 0

    enabled       = not (uac & UAC_DISABLED)
    never_expires = bool(uac & UAC_DONT_EXPIRE_PWD)
    locked        = bool(uacc & UACC_LOCKOUT)
    pwd_expired   = bool(uacc & UACC_PWD_EXPIRED)

    exp     = _filetime_to_dt(e["msDS-UserPasswordExpiryTimeComputed"].value)
    changed = _filetime_to_dt(e["pwdLastSet"].value)
    logon   = _filetime_to_dt(e["lastLogonTimestamp"].value)
    created = e["whenCreated"].value if "whenCreated" in e else None

    days = (exp - now).days if exp else None
    if never_expires:
        days = 9999
        pwd_expired = False

    if not enabled:
        state = "disabled"
    elif locked:
        state = "locked"
    elif pwd_expired or (days is not None and days <= 0):
        state = "expired"
    elif days is not None and days <= 7:
        state = "soon"
    else:
        state = "ok"

    return {
        "username": str(e["sAMAccountName"].value or ""),
        "display_name": str(e["displayName"].value or e["sAMAccountName"].value or ""),
        "mail": str(e["mail"].value or ""),
        "department": str(e["department"].value or ""),
        "title": str(e["title"].value or ""),
        "ou": _ou_of(dn),
        "dn": dn,
        "enabled": enabled,
        "locked": locked,
        "pwd_never_expires": never_expires,
        "pwd_expired": pwd_expired,
        "state": state,
        "expiry_date": exp.strftime("%-d/%-m/%Y") if exp else ("ไม่หมดอายุ" if never_expires else "-"),
        "days_left": days if days is not None else None,
        "changed_date": changed.astimezone(BKK).strftime("%-d/%-m/%Y") if changed else "-",
        "last_logon": logon.astimezone(BKK).strftime("%-d/%-m/%Y %H:%M") if logon else "-",
        "last_logon_iso": logon.isoformat() if logon else None,
        "created_date": created.astimezone(BKK).strftime("%-d/%-m/%Y") if isinstance(created, datetime) else "-",
    }


def list_users(query: str = "", limit: int = 500) -> list:
    """ค้นหา/ดึงผู้ใช้ทั้งโดเมน (query ว่าง = ทั้งหมด) ใช้ ANR ค้นชื่อ/username/อีเมล"""
    conn = _service_conn()
    out = []
    try:
        base = "(&(objectCategory=person)(objectClass=user))"
        if query:
            safe = query.replace("(", "").replace(")", "").replace("*", "")
            flt = f"(&{base}(anr={safe}))"
        else:
            flt = base
        conn.search(config.AD_BASE_DN, flt, SUBTREE,
                    attributes=_ADMIN_ATTRS, paged_size=min(limit, 1000))
        for e in conn.entries[:limit]:
            if not (e["sAMAccountName"].value):
                continue
            out.append(_entry_to_user(e))
    finally:
        conn.unbind()
    out.sort(key=lambda u: u["display_name"].lower())
    return out


def summarize(users: list) -> dict:
    s = {"total": len(users), "enabled": 0, "disabled": 0, "locked": 0,
         "expired": 0, "soon": 0, "never_expire": 0}
    for u in users:
        if u["enabled"]:
            s["enabled"] += 1
        else:
            s["disabled"] += 1
        if u["locked"]:
            s["locked"] += 1
        if u["pwd_never_expires"]:
            s["never_expire"] += 1
        if u["state"] == "expired":
            s["expired"] += 1
        elif u["state"] == "soon":
            s["soon"] += 1
    return s


def list_ous() -> list:
    """รายการ OU ทั้งหมดในโดเมน พร้อมจำนวนผู้ใช้คร่าว ๆ"""
    conn = _service_conn()
    out = []
    try:
        conn.search(config.AD_BASE_DN, "(objectClass=organizationalUnit)", SUBTREE,
                    attributes=["ou", "distinguishedName"])
        for e in conn.entries:
            dn = str(e["distinguishedName"].value)
            out.append({"name": str(e["ou"].value or ""), "dn": dn, "path": _ou_of(dn)})
    finally:
        conn.unbind()
    out.sort(key=lambda o: o["path"])
    return out


def _find_dn(conn, username: str) -> str:
    conn.search(config.AD_BASE_DN, f"(sAMAccountName={username})", SUBTREE,
                attributes=["distinguishedName", "userAccountControl"])
    if not conn.entries:
        raise LookupError("user not found")
    return conn.entries[0]


def admin_set_enabled(username: str, enabled: bool):
    conn = _service_conn()
    try:
        e = _find_dn(conn, username)
        dn = str(e["distinguishedName"].value)
        uac = int(e["userAccountControl"].value or 512)
        uac = (uac & ~UAC_DISABLED) if enabled else (uac | UAC_DISABLED)
        if not conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [uac])]}):
            raise RuntimeError(conn.result.get("description", "แก้ไขสถานะบัญชีไม่สำเร็จ"))
    finally:
        conn.unbind()


def admin_unlock(username: str):
    conn = _service_conn()
    try:
        e = _find_dn(conn, username)
        dn = str(e["distinguishedName"].value)
        if not conn.modify(dn, {"lockoutTime": [(MODIFY_REPLACE, [0])]}):
            raise RuntimeError(conn.result.get("description", "ปลดล็อกไม่สำเร็จ"))
    finally:
        conn.unbind()


def admin_reset_password(username: str, new_password: str, must_change: bool = True):
    """รีเซ็ตรหัสผ่านโดยไม่ต้องรู้รหัสเดิม (admin reset)"""
    conn = _service_conn()
    try:
        e = _find_dn(conn, username)
        dn = str(e["distinguishedName"].value)
        if not conn.extend.microsoft.modify_password(dn, new_password):
            raise RuntimeError(conn.result.get("description", "รีเซ็ตรหัสผ่านไม่สำเร็จ"))
        if must_change:
            conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
    finally:
        conn.unbind()


def admin_force_change(username: str):
    """บังคับเปลี่ยนรหัสในการล็อกอินครั้งถัดไป (pwdLastSet=0)"""
    conn = _service_conn()
    try:
        e = _find_dn(conn, username)
        dn = str(e["distinguishedName"].value)
        if not conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]}):
            raise RuntimeError(conn.result.get("description", "ตั้งค่าไม่สำเร็จ"))
    finally:
        conn.unbind()


def admin_create_user(first: str, last: str, username: str, password: str,
                      ou: str, mail: str = "", department: str = "", title: str = "",
                      must_change: bool = True, enabled: bool = True) -> dict:
    """สร้างบัญชีผู้ใช้ใหม่ใน OU ที่ระบุ"""
    display = f"{first} {last}".strip() or username
    upn = f"{username}@{config.AD_UPN_SUFFIX}"
    cn = display.replace(",", "")
    dn = f"CN={cn},{ou}"
    attrs = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "sAMAccountName": username,
        "userPrincipalName": upn,
        "displayName": display,
        "givenName": first or username,
        "sn": last or username,
    }
    if mail:
        attrs["mail"] = mail
    if department:
        attrs["department"] = department
    if title:
        attrs["title"] = title

    conn = _service_conn()
    try:
        if not conn.add(dn, attributes=attrs):
            raise RuntimeError(conn.result.get("description", "สร้างบัญชีไม่สำเร็จ") +
                               f" — {conn.result.get('message','')}")
        if not conn.extend.microsoft.modify_password(dn, password):
            raise RuntimeError("ตั้งรหัสผ่านเริ่มต้นไม่สำเร็จ: " +
                               conn.result.get("description", ""))
        uac = UAC_NORMAL_ACCOUNT if enabled else (UAC_NORMAL_ACCOUNT | UAC_DISABLED)
        conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [uac])]})
        if must_change:
            conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
    finally:
        conn.unbind()
    return {"username": username, "upn": upn, "dn": dn, "display_name": display}


def is_admin(username: str) -> bool:
    """ตรวจว่าผู้ใช้เป็นผู้ดูแลระบบ (จาก ADMIN_USERS หรือ ADMIN_GROUP)"""
    uname = (username or "").split("@")[0].split("\\")[-1].lower()
    if uname in {a.strip().lower() for a in config.ADMIN_USERS if a.strip()}:
        return True
    if not config.ADMIN_GROUP:
        return False
    conn = _service_conn()
    try:
        conn.search(config.AD_BASE_DN, f"(sAMAccountName={username})", SUBTREE,
                    attributes=["memberOf"])
        if not conn.entries:
            return False
        groups = conn.entries[0]["memberOf"].values or []
        want = config.ADMIN_GROUP.lower()
        return any(want in str(g).lower() for g in groups)
    finally:
        conn.unbind()
