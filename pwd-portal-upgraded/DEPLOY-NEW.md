# คู่มือ Deploy ตัวใหม่ (แยกจากของเดิม) — แบบละเอียด

ตัวนี้รัน **แยก stack** จากระบบเดิม รันคู่กันได้ ไม่กระทบของเดิมเลย
สิ่งที่ตั้งให้ไม่ชนกันแล้ว: ชื่อ container (`pwd-portal-v2`), ชื่อ image (`pwd-portal-v2:latest`), และ **port 8090** (เดิมใช้ 8080)

---

## 0) สรุปสิ่งที่ต่างจากของเดิม

| รายการ | ตัวเดิม | ตัวใหม่ (นี้) |
|---|---|---|
| Container | `pwd-portal` | `pwd-portal-v2` |
| Image | `pwd-portal:latest` | `pwd-portal-v2:latest` |
| Port (host) | 8080 | **8090** |
| ฟีเจอร์แอดมิน | ไม่มี | มี `/admin` |
| ค่า env ใหม่ | – | `ADMIN_USERS`, `ADMIN_GROUP`, `ADMIN_DEFAULT_OU`, `HOST_PORT` |

> ของเดิมที่รันอยู่ที่ 8080 **ไม่ต้องแตะ** ปล่อยไว้แบบนั้น

---

## 1) อัปขึ้น GitHub repo ใหม่

แตกไฟล์ zip นี้ออกมา แล้วในโฟลเดอร์โปรเจกต์รันคำสั่ง:

```bash
cd pwd-portal-upgraded        # โฟลเดอร์ที่แตกจาก zip
git init
git add .
git commit -m "pwd portal + admin console"
git branch -M main
# สร้าง repo เปล่า ๆ ใน GitHub ก่อน (เช่น pwd-portal-admin) แล้วใส่ URL ของมัน
git remote add origin https://github.com/<org-หรือ-user>/pwd-portal-admin.git
git push -u origin main
```

> ไฟล์ `.env` ถูก `.gitignore` ไว้แล้ว → ความลับ (รหัส service account / Lark secret) จะไม่ขึ้น GitHub
> ส่วนใบรับรอง `certs/bearhouse-ca.crt` คอมมิตขึ้นได้ (ไม่ใช่ความลับ) ถ้ายังไม่มีไฟล์นี้ ให้ก็อปจาก repo เดิมมาวางก่อน push

---

## 2) Deploy ลง Portainer (Stack ใหม่)

1. Portainer → **Stacks** → **Add stack** → ตั้งชื่อ `pwd-portal-v2`
2. เลือก **Repository**
   - Repository URL: URL ของ repo ใหม่ที่เพิ่ง push
   - Repository reference: `refs/heads/main`
   - Compose path: `docker-compose.yml`
3. เลื่อนลงส่วน **Environment variables** → ใส่ค่าทั้งหมด (ดูตารางข้อ 3)
4. กด **Deploy the stack** — Portainer จะ build จาก Dockerfile แล้วรันให้

> ถ้าเคยเพิ่ม Registry/credentials ของ GitHub ไว้ในตัวเดิมแล้ว ใช้ซ้ำได้เลย

---

## 3) ค่า Environment variables ที่ต้องใส่ (ละเอียด)

คัดลอกค่าจากตัวเดิมได้เกือบทั้งหมด **ของใหม่มีแค่ 4 ตัวล่าง (ADMIN_* และ HOST_PORT)**

### เหมือนตัวเดิม (ก็อปมาได้เลย)
| ตัวแปร | ตัวอย่าง | หมายเหตุ |
|---|---|---|
| `AD_HOST` | `dc01.bearhouse.sunsu.local` | FQDN ของ DC (ต้องตรงกับชื่อใน cert) |
| `AD_IP` | `192.168.0.4` | IP ของ DC — ใช้ map ชื่อในคอนเทนเนอร์ |
| `AD_PORT` | `636` | LDAPS |
| `AD_USE_SSL` | `true` | |
| `AD_BASE_DN` | `DC=bearhouse,DC=sunsu,DC=local` | |
| `AD_USER_OU` | `DC=bearhouse,DC=sunsu,DC=local` | ขอบเขตสแกนแจ้งเตือน |
| `AD_UPN_SUFFIX` | `bearhouse.sunsu.local` | |
| `AD_BIND_USER` | `svc-pwdportal@bearhouse.sunsu.local` | service account |
| `AD_BIND_PASSWORD` | (รหัสจริง) | **ความลับ** |
| `AD_TLS_VALIDATE` | `required` | ตอนทดสอบถ้า cert ยังไม่พร้อมใช้ `none` ชั่วคราว |
| `LARK_APP_ID` | `cli_xxxxxxxx` | |
| `LARK_APP_SECRET` | (secret จริง) | **ความลับ** |
| `NOTIFY_DAYS` | `14,7,3,1` | |
| `NOTIFY_HOUR` | `14` | เวลาสแกนรายวัน |
| `PORTAL_URL` | `https://pwd.bearhouse.sunsu.local` | ลิงก์ในการ์ด Lark |
| `SESSION_SECRET` | (สุ่ม 32+ ตัว) | ตั้งใหม่ ไม่ต้องเหมือนตัวเดิม |

### ✦ ใหม่ — ต้องตั้งสำหรับตัวนี้
| ตัวแปร | ตัวอย่าง | หมายเหตุ |
|---|---|---|
| `HOST_PORT` | `8090` | port ที่เปิดบนเครื่อง (อย่าใช้ 8080 ซ้ำของเดิม) |
| `ADMIN_USERS` | `administrator,nont.naraphat` | **sAMAccountName** ที่เข้า `/admin` ได้ คั่นด้วยจุลภาค — ถ้าเว้นว่าง โหมดแอดมินจะปิด |
| `ADMIN_GROUP` | *(เว้นว่างได้)* | ใช้แทน/เสริม: สมาชิกกลุ่ม AD นี้เข้าแอดมินได้ (ใส่ชื่อกลุ่ม เช่น `IT-Admins`) |
| `ADMIN_DEFAULT_OU` | *(เว้นว่างได้)* | OU เริ่มต้นตอนสร้าง user; ว่าง = ใช้ `AD_USER_OU` |

---

## 4) สิทธิ์ AD ที่ service account ต้องมี "เพิ่ม" สำหรับงานแอดมิน

ของเดิมมีแค่ Reset Password + อ่าน/เขียน `pwdLastSet` พอ
**ตัวใหม่ที่มีฟีเจอร์แอดมิน ต้องมอบสิทธิ์เพิ่ม** (ผ่าน Delegate Control ที่ OU — ไม่ต้องเป็น Domain Admin):

- Reset Password (มีอยู่แล้ว)
- Read/Write `lockoutTime` — สำหรับปุ่ม **ปลดล็อก**
- Read/Write `userAccountControl` — สำหรับ **เปิด/ปิดบัญชี**
- Read/Write `pwdLastSet` — สำหรับ **บังคับเปลี่ยนรหัส** (มีอยู่แล้ว)
- Read `msDS-User-Account-Control-Computed`, `memberOf` — อ่านสถานะล็อก/หมดอายุ และตรวจกลุ่มแอดมิน
- Create/Delete User Objects — สำหรับปุ่ม **สร้างผู้ใช้ใหม่** (มอบเฉพาะ OU ที่จะให้สร้างได้)

> ถ้ายังไม่มอบสิทธิ์เพิ่ม หน้าแอดมินยังเปิดดู/ค้นหาได้ แต่ปุ่มจัดการบางตัวจะขึ้น error เวลากด

---

## 5) ตรวจว่าใช้งานได้

1. เปิด `http://<ไอพีเครื่อง>:8090` → ควรเห็นหน้า login เดิม
2. เช็ก health: เปิด `http://<ไอพีเครื่อง>:8090/api/health` ควรได้ `{"ok":true,...}`
3. Login ด้วยบัญชีที่อยู่ใน `ADMIN_USERS` → จะเห็นเมนู **Admin Console** ขึ้นใน sidebar ซ้ายล่าง
4. กดเข้า หรือเปิดตรง ๆ ที่ `http://<ไอพีเครื่อง>:8090/admin`
5. ลองค้นหา/กรอง/เปิด panel จัดการ user ดู

> เปิด port 8090 บน firewall ของเครื่อง server ด้วย ถ้าจะเข้าจากเครื่องอื่น

---

## 6) อยากเปลี่ยน port อื่น?

แก้ค่า `HOST_PORT` ใน Environment variables (เช่น `8095`) แล้ว redeploy stack — ไม่ต้องแก้โค้ด
(ภายในคอนเทนเนอร์ยังเป็น 8080 เสมอ เปลี่ยนเฉพาะ port ฝั่งเครื่อง host)
