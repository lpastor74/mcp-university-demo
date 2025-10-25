"""
MCP Server using FastMCP with Generic OAuth 2.1 Provider
Works with: Asgardeo, Auth0, Keycloak, Okta, AWS Cognito, etc.
"""

import os
from dotenv import load_dotenv
from pydantic import AnyHttpUrl
from typing import Any, Dict, List, Optional, Tuple
import logging
from datetime import datetime
import jwt
from jwt import PyJWKClient
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi.middleware.cors import CORSMiddleware
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GenericOAuthTokenVerifier(TokenVerifier):
    """
    Generic JWT token verifier that works with any OAuth 2.1 / OIDC provider
    Supports both RS256 (JWKS) and HS256 (shared secret) algorithms
    """

    def __init__(
        self,
        jwks_url: Optional[str] = None,
        issuer: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        algorithm: str = "RS256",
        validate_audience: bool = True,
        validate_issuer: bool = True,
        ssl_verify: bool = True
    ):
        """
        Initialize the token verifier

        Args:
            jwks_url: JWKS endpoint URL (required for RS256)
            issuer: Token issuer URL (e.g., https://auth.provider.com)
            client_id: OAuth client ID (used for audience validation)
            client_secret: Client secret (required for HS256)
            algorithm: JWT algorithm (RS256 or HS256)
            validate_audience: Whether to validate audience claim
            validate_issuer: Whether to validate issuer claim
            ssl_verify: Whether to verify SSL certificates
        """
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.algorithm = algorithm
        self.validate_audience = validate_audience
        self.validate_issuer = validate_issuer
        self.ssl_verify = ssl_verify

        # Initialize JWKS client for RS256
        if self.algorithm == "RS256":
            if not self.jwks_url:
                raise ValueError("jwks_url is required for RS256 algorithm")
            self.jwks_client = PyJWKClient(
                self.jwks_url,
                cache_keys=True,
                max_cached_keys=10,
                cache_jwk_set=True
            )
        elif self.algorithm == "HS256":
            if not self.client_secret:
                raise ValueError("client_secret is required for HS256 algorithm")
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        logger.info(f"Token verifier initialized with algorithm: {algorithm}")
        logger.info(f"Issuer: {issuer}")
        logger.info(f"Audience validation: {validate_audience}")

    async def verify_token(self, token: str) -> AccessToken | None:
        """
        Verify JWT token and return AccessToken if valid
        """
        try:
            # Decode token based on algorithm
            if self.algorithm == "RS256":
                payload = await self._verify_rs256(token)
            else:
                payload = self._verify_hs256(token)

            # Extract token information
            expires_at = payload.get("exp")
            subject = payload.get("sub")
            audience = payload.get("aud")

            # Extract scopes from different possible claim names
            scopes = self._extract_scopes(payload)

            # Determine client_id (from audience or use configured)
            if isinstance(audience, str):
                client_id = audience
            elif isinstance(audience, list) and audience:
                client_id = audience[0]
            else:
                client_id = self.client_id or "unknown"

            logger.info(f"✅ Token validated for subject: {subject}")
            logger.info(f"   Scopes: {scopes}")
            logger.info(f"   Client ID: {client_id}")
            #logger.info(f"   token: {token}")

            return AccessToken(
                token=token,
                client_id=client_id,
                scopes=scopes,
                expires_at=expires_at if expires_at else None
            )

        except jwt.ExpiredSignatureError:
            logger.warning("❌ Token expired")
            return None
        except jwt.InvalidAudienceError:
            logger.warning("❌ Invalid audience")
            return None
        except jwt.InvalidIssuerError:
            logger.warning("❌ Invalid issuer")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"❌ Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Token validation error: {e}")
            return None

    async def _verify_rs256(self, token: str) -> dict:
        """Verify token using RS256 (public key from JWKS)"""
        # Get signing key from JWKS
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)

        # Build decode options
        decode_options = {
            "verify_exp": True,
            "verify_iat": True,
            "verify_aud": self.validate_audience,
            "verify_iss": self.validate_issuer
        }

        # Decode parameters
        decode_params = {
            "jwt": token,
            "key": signing_key.key,
            "algorithms": ["RS256"],
            "options": decode_options
        }

        # Add audience if validating
        if self.validate_audience and self.client_id:
            decode_params["audience"] = self.client_id

        # Add issuer if validating
        if self.validate_issuer and self.issuer:
            decode_params["issuer"] = self.issuer

        return jwt.decode(**decode_params)

    def _verify_hs256(self, token: str) -> dict:
        """Verify token using HS256 (shared secret)"""
        decode_options = {
            "verify_exp": True,
            "verify_iat": True,
            "verify_aud": self.validate_audience,
            "verify_iss": self.validate_issuer
        }

        decode_params = {
            "jwt": token,
            "key": self.client_secret,
            "algorithms": ["HS256"],
            "options": decode_options
        }

        if self.validate_audience and self.client_id:
            decode_params["audience"] = self.client_id

        if self.validate_issuer and self.issuer:
            decode_params["issuer"] = self.issuer

        return jwt.decode(**decode_params)

    def _extract_scopes(self, payload: dict) -> list[str]:
        """
        Extract scopes from token payload
        Different providers use different claim names
        """
        # Try common scope claim names
        for claim in ["scope", "scp", "scopes", "permissions"]:
            if claim in payload:
                value = payload[claim]

                # Handle space-separated string
                if isinstance(value, str):
                    return value.split()

                # Handle list
                elif isinstance(value, list):
                    return value

        return []


# ======================
# Environment Configuration
# ======================

# Authentication toggle
ENABLE_AUTH = os.getenv("ENABLE_AUTH", "true").lower() == "true"

# Required settings (only if auth is enabled)
AUTH_ISSUER = os.getenv("AUTH_ISSUER")
CLIENT_ID = os.getenv("CLIENT_ID")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8000")

MONGO_URI    = os.getenv("MONGO_URI") or os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME      = (os.getenv("DB_NAME") or "university_demo").strip().strip("/")

# Algorithm selection (RS256 or HS256)
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")

# For RS256 (most common)
JWKS_URL = os.getenv("JWKS_URL")

# For HS256 (if needed)
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

# Optional validation settings
VALIDATE_AUDIENCE = os.getenv("VALIDATE_AUDIENCE", "true").lower() == "true"
VALIDATE_ISSUER = os.getenv("VALIDATE_ISSUER", "true").lower() == "true"
SSL_VERIFY = os.getenv("SSL_VERIFY", "true").lower() == "true"

# Required scopes (optional)
REQUIRED_SCOPES_STR = os.getenv("REQUIRED_SCOPES", "")
# If no scopes are specified, default to openid and email for OIDC user info
if not REQUIRED_SCOPES_STR and ENABLE_AUTH:
    REQUIRED_SCOPES = ["openid", "email"]
else:
    REQUIRED_SCOPES = REQUIRED_SCOPES_STR.split() if REQUIRED_SCOPES_STR else []
    # Ensure openid and email are always included when auth is enabled
    if ENABLE_AUTH:
        if "openid" not in REQUIRED_SCOPES:
            REQUIRED_SCOPES.insert(0, "openid")
        if "email" not in REQUIRED_SCOPES:
            REQUIRED_SCOPES.append("email")

# Validate required environment variables only if auth is enabled
if ENABLE_AUTH:
    if not AUTH_ISSUER:
        raise ValueError("AUTH_ISSUER environment variable is required when auth is enabled")
    if not CLIENT_ID:
        raise ValueError("CLIENT_ID environment variable is required when auth is enabled")
    if JWT_ALGORITHM == "RS256" and not JWKS_URL:
        raise ValueError("JWKS_URL is required when using RS256 algorithm")
    if JWT_ALGORITHM == "HS256" and not CLIENT_SECRET:
        raise ValueError("CLIENT_SECRET is required when using HS256 algorithm")

logger.info("=" * 60)
logger.info("MCP Server Configuration")
logger.info("=" * 60)
logger.info(f"Authentication: {'ENABLED' if ENABLE_AUTH else 'DISABLED'}")
logger.info(f"Server URL: {MCP_SERVER_URL}")
if ENABLE_AUTH:
    logger.info(f"Auth Issuer: {AUTH_ISSUER}")
    logger.info(f"Client ID: {CLIENT_ID}")
    logger.info(f"Algorithm: {JWT_ALGORITHM}")
    logger.info(f"Required Scopes: {REQUIRED_SCOPES if REQUIRED_SCOPES else 'None'}")
logger.info("=" * 60)

# ======================
# Create FastMCP Instance
# ======================

if ENABLE_AUTH:
    # Create MCP server with authentication
    mcp = FastMCP(
        "Generic OAuth MCP Server",
        # Token verifier for JWT validation
        token_verifier=GenericOAuthTokenVerifier(
            jwks_url=JWKS_URL,
            issuer=AUTH_ISSUER,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            algorithm=JWT_ALGORITHM,
            validate_audience=VALIDATE_AUDIENCE,
            validate_issuer=VALIDATE_ISSUER,
            ssl_verify=SSL_VERIFY
        ),
        # Auth settings for RFC 9728 Protected Resource Metadata
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(AUTH_ISSUER),
            resource_server_url=AnyHttpUrl(MCP_SERVER_URL),
            required_scopes=REQUIRED_SCOPES if REQUIRED_SCOPES else None
        )
    )
else:
    # Create MCP server without authentication
    mcp = FastMCP("Generic OAuth MCP Server")

# ======================
# Configure CORS
# ======================

# Add CORS middleware to handle OPTIONS requests from browser clients
# Get the Starlette app instance
streamable_app = mcp.streamable_http_app()

streamable_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["mcp-session-id"],
)

logger.info("✅ CORS middleware configured")

# -------------------- Mongo --------------------
client = AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]

# -------------------- Schemas --------------------
class CreateCourseArgs(BaseModel):
   # access_token: Optional[str] = None  # optional: allow public when AUTH_DISABLED
    courseCode: str
    title: str
    semester: str = Field(pattern="^(fall|spring|summer|winter)$")
    year: int
    price: float

class ChangePriceArgs(BaseModel):
    #access_token: Optional[str] = None
    courseCode: str
    price: float

class EnrollArgs(BaseModel):
    #access_token: Optional[str] = None
    courseCode: str
    #studentId: Optional[str] = None

class StudentsDueArgs(BaseModel):
    #access_token: Optional[str] = None
    semester: str = Field(pattern="^(fall|spring|summer|winter)$")
    year: int

class MarkPaidArgs(BaseModel):
    #access_token: Optional[str] = None
    studentId: str
    courseCode: str

class MyBalanceArgs(BaseModel):
    #access_token: Optional[str] = None
    #studentId: Optional[str] = None
    semester: Optional[str] = Field(default=None, pattern="^(fall|spring|summer|winter)$")
    year: Optional[int] = None
    
# ---------- Auth helpers: claims / roles / groups ----------

def _normalize_list(v) -> list[str]:
    if not v:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return v
    if isinstance(v, dict) and "roles" in v:
        return v["roles"]
    return []

async def _current_claims() -> Optional[dict]:
    if not ENABLE_AUTH:
        return None
    ctx = mcp.get_context()
    if not ctx or not ctx.request_context or not ctx.request_context.request:
        return None
    user = ctx.request_context.request.user
    if not user or not user.access_token or not user.access_token.token:
        return None
    try:
        # already verified by FastMCP; we decode without re-verifying
        return jwt.decode(user.access_token.token, options={"verify_signature": False})
    except Exception as e:
        logger.warning(f"Failed to decode token: {e}")
        return None

def _has_any(targets: list[str], candidates: list[str]) -> bool:
    """Case-insensitive membership: any(target in candidates)."""
    if not targets or not candidates:
        return False
    tl = {t.lower() for t in targets}
    cl = {c.lower() for c in candidates}
    return bool(tl & cl)

async def user_has_role_any(*required: str) -> bool:
    """True if user has any of the required roles."""
    claims = await _current_claims()
    roles = []
    if claims:
        # common locations: "roles": [...], "realm_access":{"roles":[...]}, "cognito:groups":[...]
        roles += _normalize_list(claims.get("roles"))
        ra = claims.get("realm_access")
        if isinstance(ra, dict):
            roles += _normalize_list(ra.get("roles"))
        roles += _normalize_list(claims.get("cognito:groups"))
    return _has_any(list(required), roles)

async def user_in_group_any(*required: str) -> bool:
    """True if user is in any of the required groups."""
    claims = await _current_claims()
    groups = _normalize_list(claims.get("groups") if claims else [])
    return _has_any(list(required), groups)

# ---------- Policy decorator for tools ----------

def require_claims(role_any: list[str] | None = None,
                   group_any: list[str] | None = None):
    """
    Enforce that caller has at least ONE of the roles in role_any and/or
    belongs to at least ONE of the groups in group_any.
    If ENABLE_AUTH is False, it allows all calls.
    """
    role_any = role_any or []
    group_any = group_any or []

    def _wrap(func):
        async def _inner(*args, **kwargs):
            if not ENABLE_AUTH:
                return await func(*args, **kwargs)

            # If nothing is required, just run
            need_roles = bool(role_any)
            need_groups = bool(group_any)

            ok_roles = True
            ok_groups = True

            if need_roles:
                ok_roles = await user_has_role_any(*role_any)
            if need_groups:
                ok_groups = await user_in_group_any(*group_any)

            if (need_roles and not ok_roles) or (need_groups and not ok_groups):
                return {
                    "error": "forbidden",
                    "detail": {
                        "need_any_role": role_any if need_roles else [],
                        "need_any_group": group_any if need_groups else [],
                    }
                }

            return await func(*args, **kwargs)
        return _inner
    return _wrap

# ---------- Helpers: resolve current user & studentId from token ----------

async def _student_id_for_current_user_strict() -> str:
    """
    Resolve student's ID from the verified token's email by looking up db.students.
    No fallback, no provisioning. Raises a clear error dict to return from tools.
    """
    if not ENABLE_AUTH:
        raise RuntimeError("Authentication required to resolve student identity")

    claims = await _current_claims()
    email = _norm_email(
        (claims or {}).get("email")
        or (claims or {}).get("upn")
        or (claims or {}).get("preferred_username")
        or (claims or {}).get("unique_name")
    )
    if not email:
        raise RuntimeError("No email claim in token")

    doc = await db.students.find_one({"email": email}, {"_id": 0, "studentId": 1})
    if not doc or not doc.get("studentId"):
        raise RuntimeError(f"No student record found for email {email}")

    return doc["studentId"]

async def _current_access_token_str() -> Optional[str]:
    """
    Pull the verified access token string from FastMCP request context.
    Returns None if auth is disabled or token not present.
    """
    if not ENABLE_AUTH:
        return None
    ctx = mcp.get_context()
    if not ctx or not ctx.request_context or not ctx.request_context.request:
        return None
    u = ctx.request_context.request.user
    if not u or not u.access_token or not u.access_token.token:
        return None
    return u.access_token.token

def _norm_email(v: Optional[str]) -> Optional[str]:
    return v.strip().lower() if isinstance(v, str) else None

async def _email_from_token() -> Optional[str]:
    c = await _current_claims()
    if not c:
        return None
    return _norm_email(
        c.get("email")
        or c.get("upn")
        or c.get("preferred_username")
        or c.get("unique_name")
    )

async def _student_id_by_email(email: Optional[str]) -> Optional[str]:
    if not email:
        return None
    doc = await db.students.find_one({"email": email}, {"_id": 0, "studentId": 1})
    return (doc or {}).get("studentId")


# ======================
# Define MCP Tools
# ======================

@mcp.tool()
async def whoami() -> dict:
    """Get information about the currently authenticated user"""
    logger.info("👤 Getting user information")

    if not ENABLE_AUTH:
        return {
            "status": "unauthenticated",
            "message": "Authentication is disabled on this server"
        }

    try:
        # Access the current request context to get the token
        context = mcp.get_context()

        # Access token is available at context.request_context.request.user.access_token
        if not context or not context.request_context or not context.request_context.request:
            return {
                "status": "unauthenticated",
                "message": "No request context found"
            }

        user = context.request_context.request.user
        if not user or not user.access_token:
            return {
                "status": "unauthenticated",
                "message": "No authentication token found in request"
            }

        access_token = user.access_token
        token = access_token.token

        # Decode the JWT without verification (already verified by middleware)
        decoded = jwt.decode(token, options={"verify_signature": False})

        # Extract common OIDC claims
        user_info = {
            "sub": decoded.get("sub", "N/A"),
            "email": decoded.get("email", "N/A"),
            "email_verified": str(decoded.get("email_verified", "N/A")),
            "name": decoded.get("name", "N/A"),
            "given_name": decoded.get("given_name", "N/A"),
            "family_name": decoded.get("family_name", "N/A"),
            "preferred_username": decoded.get("preferred_username", "N/A"),
            "picture": decoded.get("picture", "N/A"),
            "scopes": " ".join(access_token.scopes) if access_token.scopes else "N/A",
            "client_id": access_token.client_id or "N/A",
            "expires_at": str(access_token.expires_at) if access_token.expires_at else "N/A"
        }

        # Remove N/A values for cleaner output
        user_info = {k: v for k, v in user_info.items() if v != "N/A"}

        logger.info(f" User: {user_info.get('email', user_info.get('sub'))}")

        return user_info

    except Exception as e:
        logger.error(f"❌ Error getting user info: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


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
@require_claims(role_any=["Academic", "Admin"])
async def create_course(args: CreateCourseArgs) -> Dict[str, Any]:
    # If auth is enabled, enforce roles
    #if ENABLE_AUTH:
        #if not args.access_token:
        #    return {"error": "missing_access_token"}
        #try:
        #    claims = await VALIDATOR.validate(args.access_token)
        #except Exception as e:
        #    return {"error": "invalid_token", "detail": str(e)}
        #roles = roles_from_claims(claims)
        #require_role(roles, "academic")
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
@require_claims(role_any=["Finance", "Admin"])
async def change_course_price(args: ChangePriceArgs) -> Dict[str, Any]:
    '''if ENABLE_AUTH:
        if not args.access_token:
            return {"error": "missing_access_token"}
        try:
            claims = await VALIDATOR.validate(args.access_token)
        except Exception as e:
            return {"error": "invalid_token", "detail": str(e)}
        roles = roles_from_claims(claims)
        require_role(roles, "finance")
        '''
    r = await db.courses.update_one({"courseCode": args.courseCode}, {"$set": {"price": args.price}})
    return {"ok": r.matched_count > 0}

@mcp.tool()
# @require_claims(role_any=["Student"], group_any=["Enroll2021"])  # optional
async def enroll(args: EnrollArgs) -> Dict[str, Any]:
    """
    Enroll the current caller (identity from token) into a course.
    Persists courseId as a DB reference (ObjectId of the course document).
    """
    # 1) Resolve studentId strictly
    try:
        sid = await _student_id_for_current_user_strict()
    except Exception as e:
        return {"error": "student_not_linked", "detail": str(e)}

    # 2) Find the course doc and price
    course = await db.courses.find_one(
        {"courseCode": args.courseCode},
        {"_id": 1, "courseCode": 1, "semester": 1, "year": 1, "price": 1}
    )
    if not course:
        return {"error": "course_not_found", "detail": f"courseCode={args.courseCode}"}

    course_oid = course["_id"]          # <-- store ObjectId reference
    sem, yr = course["semester"], course["year"]
    price = float(course.get("price", 0))

    # 3) Business rules
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

    # 4) Insert with courseId = ObjectId, NOT courseCode
    await db.enrollments.insert_one({
        "studentId": sid,
        "courseId": course_oid,     # <-- DB reference
        "semester": sem,
        "year": yr,
        "status": "enrolled",
        "isPaid": False,
        "amountDue": price,
        "createdAt": datetime.utcnow(),
    })

    return {"ok": True, "studentId": sid, "courseCode": course["courseCode"], "semester": sem, "year": yr}

    

@mcp.tool()
@require_claims(role_any=["Finance", "Admin"])
async def students_due(args: StudentsDueArgs) -> List[Dict[str, Any]]:
    pipeline = [
        {"$match": {"semester": args.semester, "year": args.year, "isPaid": False}},
        {"$lookup": {  # courseId (ObjectId) -> courses._id
            "from": "courses",
            "localField": "courseId",
            "foreignField": "_id",
            "as": "course"
        }},
        {"$unwind": "$course"},
        {"$lookup": {
            "from": "students",
            "localField": "studentId",
            "foreignField": "studentId",
            "as": "student"
        }},
        {"$unwind": "$student"},
        {"$project": {
            "_id": 0,
            "courseCode": "$course.courseCode",
            "title": "$course.title",
            "studentId": 1,
            "studentName": "$student.name",
            "studentEmail": "$student.email",
            "amountDue": 1
        }},
        {"$sort": {"courseCode": 1, "studentId": 1}},
    ]
    cur = db.enrollments.aggregate(pipeline)
    return [d async for d in cur]

@mcp.tool()
@require_claims(role_any=["Finance", "Admin"])
async def mark_paid(args: MarkPaidArgs) -> Dict[str, Any]:
    # resolve course _id by courseCode
    course = await db.courses.find_one({"courseCode": args.courseCode}, {"_id": 1})
    if not course:
        return {"error": "course_not_found", "detail": f"courseCode={args.courseCode}"}

    r = await db.enrollments.update_one(
        {"studentId": args.studentId, "courseId": course["_id"], "status": "enrolled"},
        {"$set": {"isPaid": True, "amountDue": 0.0}}
    )
    if r.matched_count == 0:
        return {"error": "enrollment_not_found"}
    return {"ok": True}

@mcp.tool()
@require_claims(role_any=["Student", "Admin"])
async def my_balance(args: MyBalanceArgs) -> Dict[str, Any]:
    # derive sid from token strictly
    try:
        sid = await _student_id_for_current_user_strict()
    except Exception as e:
        return {"error": "student_not_linked", "detail": str(e)}

    match: Dict[str, Any] = {"studentId": sid, "status": "enrolled"}
    if args.semester: match["semester"] = args.semester
    if args.year is not None: match["year"] = args.year

    pipeline = [
        {"$match": match},
        {"$lookup": {  # courseId (ObjectId) -> courses._id
            "from": "courses",
            "localField": "courseId",
            "foreignField": "_id",
            "as": "course"
        }},
        {"$unwind": "$course"},
        {"$project": {
            "_id": 0,
            "semester": 1,
            "year": 1,
            "courseCode": "$course.courseCode",
            "title": "$course.title",
            "amountDue": 1,
            "isPaid": 1
        }},
        {"$sort": {"year": 1, "semester": 1, "courseCode": 1}},
    ]
    items = [x async for x in db.enrollments.aggregate(pipeline)]
    total_due  = float(sum(x["amountDue"] for x in items if not x["isPaid"]))
    total_paid = float(sum(x["amountDue"] for x in items if x["isPaid"]))

    return {"studentId": sid, "summary": {"total_due": total_due, "total_paid": total_paid}, "lines": items}


# ======================
# Run Server
# ======================
if __name__ == "__main__":
    import uvicorn

    logger.info("🚀 Starting MCP Server with OAuth 2.1 authentication")
    logger.info(f"   Transport: streamable-http")
    logger.info(f"   Host: 127.0.0.1")
    logger.info(f"   Port: 8000")
    logger.info("=" * 60)

    uvicorn.run(streamable_app, host="127.0.0.1", port=8000)    
