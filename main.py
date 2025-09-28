import os, ssl, logging, json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from dotenv import load_dotenv

import aiohttp
import jwt

from mcp.server.fastmcp import FastMCP
from mcp.server.auth.settings import AuthSettings
from mcp.server.auth.provider import AccessToken, TokenVerifier

# -------------------- Logging --------------------
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("mcp-uni")

# -------------------- Env --------------------
load_dotenv()

RAW_ISSUER = (os.getenv("AUTH_ISSUER") or "").rstrip("/")

def to_discovery(url: str) -> str:
    if not url:
        return url
    u = url.rstrip('/')
    # If it's already a discovery URL, use as-is
    if u.endswith("/.well-known/openid-configuration"):
        return u
    # If it's exactly the issuer endpoint
    if u.endswith("/oauth2/token"):
        return u + "/.well-known/openid-configuration"
    # If it's the tenant base (no /oauth2/ segment), build the full discovery path
    if u.startswith("https://api.asgardeo.io/t/") and "/oauth2/" not in u:
        return u + "/oauth2/token/.well-known/openid-configuration"
    # Generic fallback
    return u + "/.well-known/openid-configuration"

AUTH_METADATA = to_discovery(RAW_ISSUER)
RS_URL = os.getenv("RESOURCE_SERVER_URL", "http://127.0.0.1:8000")

AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true").strip().lower() != "false"
MONGO_URI    = os.getenv("MONGO_URI") or os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME      = (os.getenv("DB_NAME") or "university_demo").strip().strip("/")


# Asgardeo OIDC
TENANT     = os.getenv("TENANT")  # e.g. metropolis
AUTH_ISSUER= os.getenv("AUTH_ISSUER")  # e.g. https://api.asgardeo.io/t/<tenant>/oauth2/token
JWKS_URL   = os.getenv("JWKS_URL")     # e.g. https://api.asgardeo.io/t/<tenant>/oauth2/jwks
CLIENT_ID  = os.getenv("CLIENT_ID")    # SPA app client_id for PKCE
#RS_URL     = os.getenv("RESOURCE_SERVER_URL", "http://127.0.0.1:8000")
SSL_VERIFY = os.getenv("SSL_VERIFY", "true").lower() != "false"
CA_BUNDLE  = os.getenv("CA_BUNDLE")

if AUTH_ENABLED and not (TENANT and AUTH_ISSUER and JWKS_URL and CLIENT_ID):
    raise RuntimeError("When AUTH_ENABLED=true, TENANT, AUTH_ISSUER, JWKS_URL, CLIENT_ID must be set")

def build_ssl_context() -> ssl.SSLContext | bool:
    if not SSL_VERIFY:
        return False
    ctx = ssl.create_default_context()
    if CA_BUNDLE and os.path.exists(CA_BUNDLE):
        ctx.load_verify_locations(CA_BUNDLE)
    return ctx

# -------------------- Mongo --------------------
client = AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]

# -------------------- JWKS validator --------------------
class JWKSValidator:
    def __init__(self, jwks_url: str, issuer: str, audience: str):
        self.jwks_url = jwks_url
        self.issuer   = issuer
        self.audience = audience
        self._jwks: Optional[Dict[str, Any]] = None

    async def _fetch_jwks(self) -> Dict[str, Any]:
        if self._jwks:
            return self._jwks
        connector = aiohttp.TCPConnector(ssl=build_ssl_context())
        async with aiohttp.ClientSession(connector=connector) as s:
            async with s.get(self.jwks_url, timeout=15) as r:
                r.raise_for_status()
                self._jwks = await r.json()
                return self._jwks

    async def validate(self, token: str) -> Dict[str, Any]:
        jwks = await self._fetch_jwks()
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if not key:
            raise ValueError("jwks_key_not_found_for_kid")
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        return jwt.decode(
            token,
            public_key,
            algorithms=[header.get("alg", "RS256")],
            audience=self.audience,
            issuer=self.issuer,
        )

VALIDATOR = JWKSValidator(JWKS_URL or "", AUTH_ISSUER or "", CLIENT_ID or "")

def roles_from_claims(claims: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for k in ("roles", "groups", "application_roles", "app_roles"):
        v = claims.get(k)
        if not v: continue
        if isinstance(v, str):
            out.extend([x.strip() for x in v.split(",") if x.strip()])
        elif isinstance(v, list):
            out.extend([str(x) for x in v])
    return sorted(set(out))

def require_role(roles: List[str], *allowed: str):
    for a in allowed:
        if a in roles:
            return
    raise PermissionError(f"no_permission (requires one of: {allowed})")

async def userinfo(token: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    issuer = (AUTH_ISSUER or "").rstrip("/")
    if not issuer:
        return None, "issuer_not_configured"
    if issuer.endswith("/token"):
        well_known = issuer[: -len("/token")] + "/.well-known/openid-configuration"
    else:
        well_known = issuer + "/.well-known/openid-configuration"
    connector = aiohttp.TCPConnector(ssl=build_ssl_context())
    try:
        async with aiohttp.ClientSession(connector=connector) as s:
            async with s.get(well_known, timeout=10) as r:
                r.raise_for_status()
                data = await r.json()
        ep = data.get("userinfo_endpoint")
        if not ep:
            return None, "userinfo_endpoint_not_configured"
        async with aiohttp.ClientSession(connector=connector) as s:
            async with s.get(ep, headers={"Authorization": f"Bearer {token}"}, timeout=15) as r:
                if r.status == 200:
                    return await r.json(), None
                return None, f"userinfo_http_{r.status}"
    except Exception as e:
        return None, f"userinfo_error_{type(e).__name__}"

async def student_id_from_token(access_token: str) -> Optional[str]:
    try:
        claims = jwt.decode(access_token, options={"verify_signature": False})
    except Exception:
        claims = {}
    email = claims.get("email") or claims.get("preferred_username") or claims.get("username")
    if not email:
        ui, err = await userinfo(access_token)
        if ui and not err:
            email = ui.get("email") or ui.get("preferred_username") or ui.get("username")
    if not email:
        return None
    s = await db.students.find_one({"email": email})
    return s["studentId"] if s else None

# -------------------- Transport token verifier (for FastMCP auth) --------------------
class AsgardeoTransportVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> Optional[AccessToken]:
        try:
            claims = await VALIDATOR.validate(token)
            scopes = claims.get("scope", "")
            return AccessToken(
                token=token,
                client_id=claims.get("aud"),
                scopes=scopes.split() if isinstance(scopes, str) else [],
                expires_at=str(claims.get("exp")) if claims.get("exp") else None,
            )
        except Exception as e:
            log.warning(f"transport token verify failed: {e}")
            return None

# -------------------- MCP server --------------------
if AUTH_ENABLED:
    mcp = FastMCP(
        "University Demo",
        token_verifier=AsgardeoTransportVerifier(),
        auth=AuthSettings(
            issuer_url=os.getenv("AUTH_ISSUER").rstrip("/"),  # <-- issuer, not discovery
            resource_server_url=os.getenv("RESOURCE_SERVER_URL", "http://127.0.0.1:8000"),
            required_scopes=["openid","profile","email","roles"],
        ),
    )
else:
    mcp = FastMCP("University Demo")



# -------------------- Schemas --------------------
class CreateCourseArgs(BaseModel):
    access_token: Optional[str] = None  # optional: allow public when AUTH_DISABLED
    courseCode: str
    title: str
    semester: str = Field(pattern="^(fall|spring|summer|winter)$")
    year: int
    price: float

class ChangePriceArgs(BaseModel):
    access_token: Optional[str] = None
    courseCode: str
    price: float

class EnrollArgs(BaseModel):
    access_token: Optional[str] = None
    courseCode: str
    studentId: Optional[str] = None

class StudentsDueArgs(BaseModel):
    access_token: Optional[str] = None
    semester: str = Field(pattern="^(fall|spring|summer|winter)$")
    year: int

class MarkPaidArgs(BaseModel):
    access_token: Optional[str] = None
    studentId: str
    courseCode: str

class MyBalanceArgs(BaseModel):
    access_token: Optional[str] = None
    studentId: Optional[str] = None
    semester: Optional[str] = Field(default=None, pattern="^(fall|spring|summer|winter)$")
    year: Optional[int] = None

# -------------------- Tools --------------------
@mcp.tool()
async def ping() -> Dict[str, str]:
    return {"ok": "pong"}

@mcp.tool()
async def list_courses() -> List[Dict[str, Any]]:
    cur = db.courses.find({}, {"_id": 0})
    return [c async for c in cur]

@mcp.tool()
async def db_counts() -> dict:
    students = await db.students.count_documents({})
    courses = await db.courses.count_documents({})
    enrolls = await db.enrollments.count_documents({})
    return {"students": students, "courses": courses, "enrollments": enrolls}

@mcp.tool()
async def whoami_token(access_token: str) -> Dict[str, Any]:
    """Validate a token and show claims/roles (useful in Claude to capture the bearer)."""
    if not AUTH_ENABLED:
        return {"valid": False, "error": "auth_disabled"}
    try:
        claims = await VALIDATOR.validate(access_token)
        return {"valid": True, "claims": claims, "roles": roles_from_claims(claims)}
    except Exception as e:
        return {"valid": False, "error": str(e)}

@mcp.tool()
async def create_course(args: CreateCourseArgs) -> Dict[str, Any]:
    # If auth is enabled, enforce roles
    if AUTH_ENABLED:
        if not args.access_token:
            return {"error": "missing_access_token"}
        try:
            claims = await VALIDATOR.validate(args.access_token)
        except Exception as e:
            return {"error": "invalid_token", "detail": str(e)}
        roles = roles_from_claims(claims)
        require_role(roles, "academic")
    # create
    if await db.courses.find_one({"courseCode": args.courseCode}):
        return {"error": "course_exists"}
    await db.courses.insert_one({
        "courseCode": args.courseCode,
        "title": args.title,
        "semester": args.semester,
        "year": args.year,
        "price": args.price,
    })
    return {"ok": True}

@mcp.tool()
async def change_course_price(args: ChangePriceArgs) -> Dict[str, Any]:
    if AUTH_ENABLED:
        if not args.access_token:
            return {"error": "missing_access_token"}
        try:
            claims = await VALIDATOR.validate(args.access_token)
        except Exception as e:
            return {"error": "invalid_token", "detail": str(e)}
        roles = roles_from_claims(claims)
        require_role(roles, "finance")
    r = await db.courses.update_one({"courseCode": args.courseCode}, {"$set": {"price": args.price}})
    return {"ok": r.matched_count > 0}

@mcp.tool()
async def enroll(args: EnrollArgs) -> Dict[str, Any]:
    if AUTH_ENABLED:
        if not args.access_token:
            return {"error": "missing_access_token"}
        try:
            claims = await VALIDATOR.validate(args.access_token)
        except Exception as e:
            return {"error": "invalid_token", "detail": str(e)}
        roles = roles_from_claims(claims)
        require_role(roles, "student")
        sid = args.studentId or await student_id_from_token(args.access_token)
    else:
        sid = args.studentId
    if not sid:
        return {"error": "student_not_linked"}
    course = await db.courses.find_one({"courseCode": args.courseCode})
    if not course:
        return {"error": "course_not_found"}

    sem, yr = course["semester"], course["year"]
    unpaid_prev = await db.enrollments.count_documents({
        "studentId": sid, "isPaid": False,
        "$or": [{"year": {"$lt": yr}}, {"year": yr, "semester": {"$ne": sem}}],
    })
    if unpaid_prev > 0:
        return {"error": "has_unpaid_balance_previous_semesters"}

    current = await db.enrollments.count_documents({
        "studentId": sid, "semester": sem, "year": yr, "status": "enrolled"
    })
    if current >= 5:
        return {"error": "max_courses_reached"}

    await db.enrollments.insert_one({
        "studentId": sid,
        "courseId": course["courseCode"],
        "semester": sem,
        "year": yr,
        "status": "enrolled",
        "isPaid": False,
        "amountDue": float(course["price"]),
        "createdAt": datetime.utcnow(),
    })
    return {"ok": True, "studentId": sid}

@mcp.tool()
async def students_due(args: StudentsDueArgs) -> List[Dict[str, Any]]:
    if AUTH_ENABLED:
        if not args.access_token:
            return [{"error": "missing_access_token"}]
        try:
            claims = await VALIDATOR.validate(args.access_token)
        except Exception as e:
            return [{"error": "invalid_token", "detail": str(e)}]
        roles = roles_from_claims(claims)
        require_role(roles, "finance")
    cur = db.enrollments.aggregate([
        {"$match": {"semester": args.semester, "year": args.year, "isPaid": False}},
        {"$lookup": {"from": "courses", "localField": "courseId", "foreignField": "courseCode", "as": "course"}},
        {"$unwind": "$course"},
        {"$lookup": {"from": "students", "localField": "studentId", "foreignField": "studentId", "as": "student"}},
        {"$unwind": "$student"},
        {"$project": {
            "_id": 0,
            "courseCode": "$course.courseCode", "title": "$course.title",
            "studentId": 1, "studentName": "$student.name", "studentEmail": "$student.email",
            "amountDue": 1
        }},
        {"$sort": {"courseCode": 1, "studentId": 1}},
    ])
    return [d async for d in cur]

@mcp.tool()
async def mark_paid(args: MarkPaidArgs) -> Dict[str, Any]:
    if AUTH_ENABLED:
        if not args.access_token:
            return {"error": "missing_access_token"}
        try:
            claims = await VALIDATOR.validate(args.access_token)
        except Exception as e:
            return {"error": "invalid_token", "detail": str(e)}
        roles = roles_from_claims(claims)
        require_role(roles, "finance")
    r = await db.enrollments.update_one(
        {"studentId": args.studentId, "courseId": args.courseCode, "status": "enrolled"},
        {"$set": {"isPaid": True, "amountDue": 0.0}},
    )
    if r.matched_count == 0:
        return {"error": "enrollment_not_found"}
    return {"ok": True}

@mcp.tool()
async def my_balance(args: MyBalanceArgs) -> Dict[str, Any]:
    if AUTH_ENABLED:
        if not args.access_token:
            return {"error": "missing_access_token"}
        try:
            claims = await VALIDATOR.validate(args.access_token)
        except Exception as e:
            return {"error": "invalid_token", "detail": str(e)}
        roles = roles_from_claims(claims)
        require_role(roles, "student")
        sid = args.studentId or await student_id_from_token(args.access_token)
    else:
        sid = args.studentId
    if not sid:
        return {"error": "student_not_linked"}

    match: Dict[str, Any] = {"studentId": sid, "status": "enrolled"}
    if args.semester: match["semester"] = args.semester
    if args.year is not None: match["year"] = args.year

    pipeline = [
        {"$match": match},
        {"$lookup": {"from": "courses", "localField": "courseId", "foreignField": "courseCode", "as": "course"}},
        {"$unwind": "$course"},
        {"$project": {
            "_id": 0,
            "semester": 1, "year": 1,
            "courseCode": "$course.courseCode", "title": "$course.title",
            "amountDue": 1, "isPaid": 1
        }},
        {"$sort": {"year": 1, "semester": 1, "courseCode": 1}},
    ]
    items = [x async for x in db.enrollments.aggregate(pipeline)]
    total_due  = float(sum(x["amountDue"] for x in items if not x["isPaid"]))
    total_paid = float(sum(x["amountDue"] for x in items if x["isPaid"]))

    return {
        "studentId": sid,
        "summary": {"total_due": total_due, "total_paid": total_paid},
        "lines": items,
    }




# -------------------- Run --------------------
if __name__ == "__main__":
    mcp.run(transport="streamable-http")

#if __name__ == "__main__":
#    mcp.run(transport="stdio")    