from __future__ import annotations
import os, sqlite3, json, re
from datetime import datetime, timedelta
from typing import Tuple, List, Dict, Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from google.oauth2 import service_account
from googleapiclient.discovery import build

app = FastAPI(title="Google Sheets CRUD + Auth API (Multi-Sheet + Audit)")
ALLOWED_ORIGINS = "https://khichi-orpin.vercel.app"
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
SERVICE_ACCOUNT_FILE = os.getenv("SERVICE_ACCOUNT_FILE", "service_account.json")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
DB_PATH = os.getenv("DB_PATH", "app.db")
def db_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    with db_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT
        )
        """)
        cur.execute("SELECT COUNT(*) FROM config WHERE key='sheets'")
        if cur.fetchone()[0] == 0:
            default_sheets = {
                "pickup_11_sept": {"sheet_id": "1KsSPQafhRaT6pNOEQYDdG5UJZ_1fPS8nbPNMes9YL3U", "tab": "11 Sept Pickup"},
                "thursday_appointments": {"sheet_id": "1KsSPQafhRaT6pNOEQYDdG5UJZ_1fPS8nbPNMes9YL3U", "tab": "Thursday Appointments"},
                "packing_list": {"sheet_id": "1KsSPQafhRaT6pNOEQYDdG5UJZ_1fPS8nbPNMes9YL3U", "tab": "Packing List"},
                "for_labels": {"sheet_id": "1KsSPQafhRaT6pNOEQYDdG5UJZ_1fPS8nbPNMes9YL3U", "tab": "For Labels"},
                "shipping": {"sheet_id": "1aql7sYqD8bcnscurfjNZcN2H5jIUKHhBczyA7Fi9FKI", "tab": "Shipping"},
                "unpaid": {"sheet_id": "1aql7sYqD8bcnscurfjNZcN2H5jIUKHhBczyA7Fi9FKI", "tab": "Unpaid"},
            }
            cur.execute(
                "INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)",
                ("sheets", json.dumps(default_sheets), datetime.utcnow().isoformat()),
            )
        conn.commit()
init_db()

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str):
    with db_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role, created_at FROM users WHERE username=?", (username,))
        return cur.fetchone()

def authenticate_user(username: str, password: str):
    row = get_user(username)
    if not row:
        return False
    _id, _uname, hashed_pw, _role, _created = row
    if not verify_password(password, hashed_pw):
        return False
    return row

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = get_user(username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def ensure_admin(current):
    if not current or len(current) < 4:
        raise HTTPException(status_code=403, detail="Forbidden")
    if current[3] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
credentials = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=["https://www.googleapis.com/auth/spreadsheets"]
)
def get_service():
    return build("sheets", "v4", credentials=credentials, cache_discovery=False)

def get_sheets_config() -> Dict[str, Dict[str, str]]:
    with db_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM config WHERE key='sheets'")
        row = cur.fetchone()
        return json.loads(row[0]) if row else {}

def ensure_sheet_key(sheet_key: str):
    sheets = get_sheets_config()
    if sheet_key not in sheets:
        raise HTTPException(status_code=404, detail=f"Invalid sheet key: {sheet_key}")
    cfg = sheets[sheet_key]
    return cfg["sheet_id"], cfg["tab"]

def col_index_to_letter(idx: int) -> str:
    letters = ""
    while idx:
        idx, remainder = divmod(idx - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters

def get_headers_with_audit(sheet_id: str, range_name: str):
    """
    Ensure header row contains 'ModifiedBy' and 'ModifiedAt' (case-insensitive),
    and return (headers, modifiedby_index, modifiedat_index).
    """
    sheet = get_service().spreadsheets()
    header_range = f"{range_name}!1:1"
    resp = sheet.values().get(spreadsheetId=sheet_id, range=header_range).execute()
    values = resp.get("values", [])
    headers = values[0] if values else []

    normalized = [str(h or "").strip().lower() for h in headers]
    changed = False

    if "modifiedby" not in normalized:
        headers.append("ModifiedBy")
        normalized.append("modifiedby")
        changed = True
    if "modifiedat" not in normalized:
        headers.append("ModifiedAt")
        normalized.append("modifiedat")
        changed = True

    if changed:
        sheet.values().update(
            spreadsheetId=sheet_id,
            range=header_range,
            valueInputOption="USER_ENTERED",
            body={"values": [headers]},
        ).execute()

    mby_idx = normalized.index("modifiedby")
    mat_idx = normalized.index("modifiedat")
    return headers, mby_idx, mat_idx

class RowData(BaseModel):
    values: List[str]

class SignupModel(BaseModel):
    username: str
    password: str
    role: str | None = None

class LoginModel(BaseModel):
    username: str
    password: str

class ConfigUpdate(BaseModel):
    sheets: dict

class NewUser(BaseModel):
    username: str
    password: str
    role: str = "user"

class UserCredUpdate(BaseModel):
    old_username: str
    old_password: Optional[str] = None
    new_username: Optional[str] = None
    new_password: Optional[str] = None

class KPIUpdate(BaseModel):
    kpis: Dict[str, str | float | int]

@app.get("/fetch/{sheet_key}")
def fetch_data(sheet_key: str, user: Tuple = Depends(get_current_user)):
    """
    Returns rows with:
      - Display values for all headers
      - Adds `<Header>$link` fields for cells that have a HYPERLINK formula or rich-text hyperlink
      - Adds `_links = { Header: url, ... }` convenience dict
      - Adds `_sheetRow` (1-based row index in the sheet)
    """
    sheet_id, range_name = ensure_sheet_key(sheet_key)
    try:
        svc = get_service().spreadsheets()
        values_api = svc.values()

        formatted_resp = values_api.get(
            spreadsheetId=sheet_id,
            range=range_name,
            valueRenderOption="FORMATTED_VALUE",
            dateTimeRenderOption="FORMATTED_STRING",
        ).execute()
        formatted_vals = formatted_resp.get("values", []) or []
        if not formatted_vals:
            return {"data": []}

        formula_resp = values_api.get(
            spreadsheetId=sheet_id,
            range=range_name,
            valueRenderOption="FORMULA",
            dateTimeRenderOption="FORMATTED_STRING",
        ).execute()
        formula_vals = formula_resp.get("values", []) or []

        headers = formatted_vals[0]
        formatted_rows = formatted_vals[1:]
        formula_rows = formula_vals[1:] if len(formula_vals) > 1 else []

        grid_resp = svc.get(
            spreadsheetId=sheet_id,
            ranges=[range_name],
            includeGridData=True,
        ).execute()
        row_data = []
        try:
            row_data = (
                grid_resp.get("sheets", [])[0]
                .get("data", [])[0]
                .get("rowData", [])
            )
        except Exception:
            row_data = []

        def parse_hyperlink_url(expr: str) -> str:
            if not isinstance(expr, str):
                return ""
            if not expr.upper().startswith("=HYPERLINK("):
                return ""
            inner = expr[11:].rstrip(")")
            m = re.match(r'^\s*"([^"]+)"', inner)
            if m:
                return m.group(1).strip()
            parts = inner.split("," if "," in inner else ";", 1)
            if parts:
                return parts[0].strip().strip('"').strip("'")
            return ""

        out = []
        for r_index, f_row in enumerate(formatted_rows, start=2): 
            p_row = formula_rows[r_index - 2] if r_index - 2 < len(formula_rows) else []
            rec = {"_sheetRow": r_index}
            link_bucket = {}
            for c, header in enumerate(headers):
                disp = f_row[c] if c < len(f_row) else ""
                form = p_row[c] if c < len(p_row) else ""
                rec[header] = disp

                url = parse_hyperlink_url(form)
                if url:
                    rec[f"{header}$link"] = url
                    link_bucket[header] = url

            gd_row_idx = r_index - 1
            if 0 <= gd_row_idx < len(row_data):
                gd_row = row_data[gd_row_idx]
                cells = gd_row.get("values", [])
                for c, header in enumerate(headers):
                    if c >= len(cells):
                        continue
                    cell = cells[c] or {}
                    cell_url = cell.get("hyperlink")
                    if cell_url:
                        rec[f"{header}$link"] = cell_url
                        link_bucket[header] = cell_url
                        continue
                    runs = cell.get("textFormatRuns") or []
                    for run in runs:
                        fmt = (run or {}).get("format") or {}
                        link = fmt.get("link") or {}
                        uri = link.get("uri")
                        if uri:
                            rec[f"{header}$link"] = uri
                            link_bucket[header] = uri
                            break

            if link_bucket:
                rec["_links"] = link_bucket

            out.append(rec)

        return {"data": out}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fetch failed: {e}")

@app.post("/add/{sheet_key}")
def add_row(sheet_key: str, row: RowData, user: Tuple = Depends(get_current_user)):
    sheet_id, range_name = ensure_sheet_key(sheet_key)
    username = user[1]
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        headers, mby_idx, mat_idx = get_headers_with_audit(sheet_id, range_name)
        vals = list(row.values)
        if len(vals) < len(headers):
            vals += [""] * (len(headers) - len(vals))
        else:
            vals = vals[:len(headers)]
        vals[mby_idx] = username
        vals[mat_idx] = timestamp

        get_service().spreadsheets().values().append(
            spreadsheetId=sheet_id,
            range=range_name,
            valueInputOption="USER_ENTERED",
            insertDataOption="INSERT_ROWS",
            body={"values": [vals]},
        ).execute()
        return {"message": "Row added successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Add failed: {e}")

@app.put("/kpis/{sheet_key}")
def put_kpis(sheet_key: str, payload: KPIUpdate, user: Tuple = Depends(get_current_user)):
    """
    Update KPI block values that live next to their labels
    (e.g., 'Pickup Complete' in column L, value in column M).
    We scan for each label's cell and write to the cell immediately to the right.
    """
    sheet_id, range_name = ensure_sheet_key(sheet_key)
    svc = get_service().spreadsheets()
    resp = svc.values().get(spreadsheetId=sheet_id, range=range_name).execute()
    matrix = resp.get("values", []) or []
    positions: Dict[str, Tuple[int, int]] = {}
    wanted = set(map(str, payload.kpis.keys()))
    for r_idx, row in enumerate(matrix, start=1):
        if not wanted:
            break
        for c_idx, cell in enumerate(row, start=1):
            text = (cell or "").strip()
            if text in wanted:
                positions[text] = (r_idx, c_idx + 1)  
                wanted.discard(text)
    updates = []
    for label, value in payload.kpis.items():
        pos = positions.get(label)
        if not pos:
            continue
        r, c = pos
        a1 = f"{range_name}!{col_index_to_letter(c)}{r}"
        updates.append({"range": a1, "values": [[str(value)]]})

    if not updates:
        return {"message": "No KPI labels found to update", "updated": []}

    svc.values().batchUpdate(
        spreadsheetId=sheet_id,
        body={"valueInputOption": "USER_ENTERED", "data": updates},
    ).execute()

    return {"message": "KPI cells updated", "updated": [u["range"] for u in updates]}

@app.put("/update/{sheet_key}/{row_index}")
def update_row(sheet_key: str, row_index: int, row: RowData, user: Tuple = Depends(get_current_user)):
    sheet_id, range_name = ensure_sheet_key(sheet_key)
    username = user[1]
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        headers, mby_idx, mat_idx = get_headers_with_audit(sheet_id, range_name)
        vals = list(row.values)
        if len(vals) < len(headers):
            vals += [""] * (len(headers) - len(vals))
        else:
            vals = vals[:len(headers)]
        vals[mby_idx] = username
        vals[mat_idx] = timestamp

        end_col = col_index_to_letter(max(1, len(headers)))
        a1 = f"{range_name}!A{row_index}:{end_col}{row_index}"

        get_service().spreadsheets().values().update(
            spreadsheetId=sheet_id,
            range=a1,
            valueInputOption="USER_ENTERED",
            body={"values": [vals]},
        ).execute()
        return {"message": f"Row {row_index} updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Update failed: {e}")

@app.delete("/delete/{sheet_key}/{row_index}")
def delete_row(sheet_key: str, row_index: int, user: Tuple = Depends(get_current_user)):
    sheet_id, range_name = ensure_sheet_key(sheet_key)
    try:
        sheet = get_service().spreadsheets()
        values = sheet.values().get(spreadsheetId=sheet_id, range=range_name).execute().get("values", [])
        if not values:
            raise HTTPException(status_code=404, detail="Sheet is empty")
        max_cols = max(len(r) for r in values) if values else 26
        end_col = col_index_to_letter(max_cols)
        a1 = f"{range_name}!A{row_index}:{end_col}{row_index}"
        sheet.values().clear(spreadsheetId=sheet_id, range=a1, body={}).execute()
        return {"message": f"Row {row_index} deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Delete failed: {e}")

@app.post("/signup")
def signup(user: SignupModel):
    if not user.username or not user.password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    try:
        with db_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM users WHERE username=?", (user.username,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="Username already exists")
            hashed = get_password_hash(user.password)
            role = user.role or "user"
            created_at = datetime.utcnow().isoformat()
            cur.execute(
                "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
                (user.username, hashed, role, created_at),
            )
            conn.commit()
        return {"message": "User registered successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signup failed: {e}")

@app.post("/login")
def login(user: LoginModel):
    row = authenticate_user(user.username, user.password)
    if not row:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me")
def me(current: Tuple = Depends(get_current_user)):
    _id, username, _hash, role, created_at = current
    return {"id": _id, "username": username, "role": role, "created_at": created_at}

@app.get("/users")
def users_list(current: Tuple = Depends(get_current_user)):
    ensure_admin(current)
    with db_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT username, role, created_at FROM users ORDER BY created_at DESC")
        rows = [{"username": u, "role": r, "created_at": c} for (u, r, c) in cur.fetchall()]
        return {"data": rows}

@app.post("/users")
def users_add(payload: NewUser, current: Tuple = Depends(get_current_user)):
    ensure_admin(current)
    return signup(SignupModel(username=payload.username, password=payload.password, role=payload.role))

@app.delete("/users/{username}")
def users_delete(username: str, current: Tuple = Depends(get_current_user)):
    ensure_admin(current)
    with db_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE username=?", (username,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
        conn.commit()
    return {"message": "User deleted"}

@app.put("/users/credentials")
def users_update_credentials(payload: UserCredUpdate, current: Tuple = Depends(get_current_user)):
    """
    Admin can change a user's username and/or password.
    - old_password is OPTIONAL for admins (if provided, it's verified).
    - Ensures new username, if given, is unique.
    """
    ensure_admin(current)

    if not payload.old_username:
        raise HTTPException(status_code=400, detail="Username to update is required")

    row = get_user(payload.old_username)
    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    user_id, old_uname, old_hash, role, created_at = row
    if payload.old_password:
        if not verify_password(payload.old_password, old_hash):
            raise HTTPException(status_code=400, detail="Old password is incorrect")

    new_uname = payload.new_username.strip() if payload.new_username else old_uname
    new_hash = get_password_hash(payload.new_password) if payload.new_password else old_hash
    if new_uname != old_uname:
        with db_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM users WHERE username=?", (new_uname,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="New username already exists")
    with db_conn() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET username=?, password=? WHERE id=?", (new_uname, new_hash, user_id))
        conn.commit()

    return {"message": "Credentials updated", "username": new_uname}

@app.get("/config/sheets")
def get_config(current: Tuple = Depends(get_current_user)):
    ensure_admin(current)
    return {"sheets": get_sheets_config()}

@app.put("/config/sheets")
def put_config(payload: ConfigUpdate, current: Tuple = Depends(get_current_user)):
    ensure_admin(current)
    if not isinstance(payload.sheets, dict):
        raise HTTPException(status_code=400, detail="Invalid sheets payload")
    username = current[1]
    try:
        with db_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO config (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                ("sheets", json.dumps(payload.sheets), datetime.utcnow().isoformat(), username),
            )
            conn.commit()
        return {"message": "Configuration updated successfully", "sheets": payload.sheets}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Config update failed: {e}")

@app.get("/")
def home():
    return {
        "message": "Google Sheets CRUD + Auth API running! (Multi-Sheet Mode)",
        "sheets": list(get_sheets_config().keys()),
    }
