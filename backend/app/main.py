from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, create_engine, inspect, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from .agents.planner import create_plan


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./backend/sentinelai.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
APP_SECRET = os.getenv("APP_SECRET", "sentinelai-local-demo-secret-change-me")
DEMO_HOST_ALLOWLIST = {"travelcore.local", "127.0.0.1", "localhost", "testserver"}


class Base(DeclarativeBase):
    pass


class SchemaMigration(Base):
    __tablename__ = "schema_migrations"
    version: Mapped[str] = mapped_column(String(40), primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Agency(Base):
    __tablename__ = "agencies"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(160), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(40))
    agency_id: Mapped[int] = mapped_column(ForeignKey("agencies.id"))
    password_hash: Mapped[str] = mapped_column(String(128))


class Flight(Base):
    __tablename__ = "flights"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(20))
    origin: Mapped[str] = mapped_column(String(80))
    destination: Mapped[str] = mapped_column(String(80))
    departure: Mapped[str] = mapped_column(String(80))
    price: Mapped[float] = mapped_column(Float)
    seats: Mapped[int] = mapped_column(Integer, default=14)


class Booking(Base):
    __tablename__ = "bookings"
    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(32), unique=True)
    agency_id: Mapped[int] = mapped_column(ForeignKey("agencies.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    flight_id: Mapped[int] = mapped_column(ForeignKey("flights.id"))
    traveller: Mapped[str] = mapped_column(String(120))
    amount: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(40), default="confirmed")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Ledger(Base):
    __tablename__ = "ledger"
    id: Mapped[int] = mapped_column(primary_key=True)
    booking_id: Mapped[int] = mapped_column(ForeignKey("bookings.id"))
    kind: Mapped[str] = mapped_column(String(40))
    amount: Mapped[float] = mapped_column(Float)
    reference: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class DemoConfig(Base):
    __tablename__ = "demo_config"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(String(240))


class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[int] = mapped_column(primary_key=True)
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(200), index=True)
    workflow: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(60))
    auth_required: Mapped[bool] = mapped_column(Boolean, default=True)
    classification: Mapped[str] = mapped_column(String(20), default="Active")
    source: Mapped[str] = mapped_column(String(60), default="Seeded route catalogue")
    last_seen: Mapped[str] = mapped_column(String(40), default="Just now")
    parameters: Mapped[list] = mapped_column(JSON, default=list)


class WorkflowGraph(Base):
    __tablename__ = "workflows"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    nodes: Mapped[list] = mapped_column(JSON, default=list)
    edges: Mapped[list] = mapped_column(JSON, default=list)
    endpoint_refs: Mapped[list] = mapped_column(JSON, default=list)
    business_criticality: Mapped[str] = mapped_column(String(20), default="Medium")


class AuthorizationPolicy(Base):
    __tablename__ = "authorization_policies"
    id: Mapped[int] = mapped_column(primary_key=True)
    role: Mapped[str] = mapped_column(String(50))
    action: Mapped[str] = mapped_column(String(120))
    decision: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    source: Mapped[str] = mapped_column(String(100), default="Seeded ground truth")


class Deployment(Base):
    __tablename__ = "deployments"
    id: Mapped[int] = mapped_column(primary_key=True)
    version: Mapped[str] = mapped_column(String(40))
    scenario: Mapped[str] = mapped_column(String(40))
    changes: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(String(30), default="Running")
    scenario: Mapped[str] = mapped_column(String(40))
    version: Mapped[str] = mapped_column(String(40))
    progress: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class AttackPlan(Base):
    __tablename__ = "attack_plans"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    scenario: Mapped[str] = mapped_column(String(40))
    endpoint: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(60))
    reason: Mapped[str] = mapped_column(Text)
    principal: Mapped[str] = mapped_column(String(160))
    preconditions: Mapped[list] = mapped_column(JSON, default=list)
    procedure: Mapped[list] = mapped_column(JSON, default=list)
    expected_result: Mapped[str] = mapped_column(Text)
    verification_criteria: Mapped[str] = mapped_column(Text)
    risk_level: Mapped[str] = mapped_column(String(20))
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False)
    workflow: Mapped[str] = mapped_column(String(160))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    title: Mapped[str] = mapped_column(String(180))
    category: Mapped[str] = mapped_column(String(60))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(30), default="Verified")
    endpoint: Mapped[str] = mapped_column(String(200))
    agency: Mapped[str] = mapped_column(String(100))
    confidence: Mapped[float] = mapped_column(Float, default=0.99)
    business_impact: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_factors: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str] = mapped_column(Text)
    regression_test: Mapped[str] = mapped_column(Text)
    workflow: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class RetestRun(Base):
    __tablename__ = "retest_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    result: Mapped[str] = mapped_column(String(30))
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Event(Base):
    __tablename__ = "agent_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    category: Mapped[str] = mapped_column(String(20), default="INFO")
    message: Mapped[str] = mapped_column(String(280))
    scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Audit(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    principal: Mapped[str] = mapped_column(String(120))
    method: Mapped[str] = mapped_column(String(10))
    target: Mapped[str] = mapped_column(String(240))
    purpose: Mapped[str] = mapped_column(String(120))
    outcome: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


def pwd_hash(password: str) -> str:
    salt=secrets.token_hex(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),(APP_SECRET+salt).encode(),120_000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        salt,expected=encoded.split("$",1)
        actual=hashlib.pbkdf2_hmac("sha256",password.encode(),(APP_SECRET+salt).encode(),120_000).hex()
        return hmac.compare_digest(expected,actual)
    except Exception:
        return False


def make_token(user: User) -> str:
    payload = f"{user.id}:{int(time.time()) + 86400}"
    sig = hmac.new(APP_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def decode_token(token: str) -> int:
    try:
        user_id, expires, sig = token.split(":")
        payload = f"{user_id}:{expires}"
        expected = hmac.new(APP_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig) or int(expires) < int(time.time()):
            raise ValueError()
        return int(user_id)
    except Exception as exc:
        raise HTTPException(401, "Invalid or expired session") from exc


def db_session():
    with SessionLocal() as session:
        yield session


def seed(db: Session):
    if db.scalar(select(Agency.id).limit(1)):
        for seeded_email in ("admin@northstar.demo","agent@northstar.demo","admin@meridian.demo","agent@meridian.demo"):
            existing=db.scalar(select(User).where(User.email==seeded_email))
            if existing and "$" not in existing.password_hash:
                existing.password_hash=pwd_hash("Sentinel123!")
        if not db.scalar(select(WorkflowGraph.id).limit(1)):
            db.add_all([
                WorkflowGraph(name="Search & Booking",nodes=["Flight search","Booking","Payment"],edges=[["Flight search","Booking"],["Booking","Payment"]],endpoint_refs=["GET /api/travel/flights","POST /api/travel/bookings","GET /api/travel/bookings/{booking_id}"],business_criticality="High"),
                WorkflowGraph(name="Cancellation & Refund",nodes=["Booking","Cancellation","Refund"],edges=[["Booking","Cancellation"],["Cancellation","Refund"]],endpoint_refs=["GET /api/travel/bookings/{booking_id}","POST /api/travel/bookings/{booking_id}/cancel","POST /api/travel/bookings/{booking_id}/refund"],business_criticality="Critical"),
                WorkflowGraph(name="Agency Administration",nodes=["Authentication","Role management"],edges=[["Authentication","Role management"]],endpoint_refs=["GET /api/travel/users"],business_criticality="High"),
            ])
        if not db.scalar(select(AuthorizationPolicy.id).limit(1)):
            for role, action, decision, confidence, source in [("Agency Admin","View own agency bookings","Allowed",1.0,"Seeded ground truth"),("Booking Agent","View own agency bookings","Allowed",1.0,"Seeded ground truth"),("Agency Admin","View another agency bookings","Denied",1.0,"Seeded ground truth"),("Booking Agent","View another agency bookings","Denied",1.0,"Seeded ground truth"),("Agency Admin","Manage agency users","Allowed",1.0,"Seeded ground truth"),("Booking Agent","Manage agency users","Denied",1.0,"Seeded ground truth"),("Agency Admin","Modify platform settings","Review",0.62,"Inferred; human review required"),("Booking Agent","Modify platform settings","Denied",1.0,"Seeded ground truth")]:
                db.add(AuthorizationPolicy(role=role,action=action,decision=decision,confidence=confidence,source=source))
        db.commit()
        return
    a = Agency(id=1, name="Northstar Travel"); b = Agency(id=2, name="Meridian Journeys")
    db.add_all([a, b]); db.flush()
    users = [
        User(id=1, email="admin@northstar.demo", name="Priya Sharma", role="Agency Admin", agency_id=1, password_hash=pwd_hash("Sentinel123!")),
        User(id=2, email="agent@northstar.demo", name="Arjun Mehta", role="Booking Agent", agency_id=1, password_hash=pwd_hash("Sentinel123!")),
        User(id=3, email="admin@meridian.demo", name="Maya Iyer", role="Agency Admin", agency_id=2, password_hash=pwd_hash("Sentinel123!")),
        User(id=4, email="agent@meridian.demo", name="Kabir Rao", role="Booking Agent", agency_id=2, password_hash=pwd_hash("Sentinel123!")),
    ]
    db.add_all(users)
    flights = [Flight(id=1, code="AI 401", origin="Mumbai", destination="Delhi", departure="09:15", price=12000, seats=14), Flight(id=2, code="UK 822", origin="Bengaluru", destination="Mumbai", departure="13:40", price=8400, seats=9), Flight(id=3, code="6E 218", origin="Delhi", destination="Goa", departure="18:20", price=6700, seats=22)]
    db.add_all(flights); db.flush()
    db.add_all([Booking(id=101, reference="TC-NS-101", agency_id=1, user_id=2, flight_id=1, traveller="Aarav Shah", amount=12000, status="confirmed"), Booking(id=202, reference="TC-MJ-202", agency_id=2, user_id=4, flight_id=2, traveller="Ananya Rao", amount=8400, status="confirmed"), Booking(id=303, reference="TC-NS-303", agency_id=1, user_id=1, flight_id=3, traveller="Rohan Kapoor", amount=6700, status="cancelled")])
    db.add(Ledger(booking_id=303, kind="payment", amount=6700, reference="PAY-303"))
    for key, value in {"idor":"secure", "fare":"secure", "refund":"secure", "version":"v1.0.0", "scan_paused":"false"}.items(): db.add(DemoConfig(key=key, value=value))
    db.add_all([Endpoint(method="GET", path="/api/travel/flights", workflow="Search & Booking", role="Booking Agent", parameters=["origin", "destination"]), Endpoint(method="GET", path="/api/travel/bookings/{booking_id}", workflow="Booking & Authorization", role="Booking Agent", parameters=["booking_id"]), Endpoint(method="POST", path="/api/travel/bookings", workflow="Search → Booking → Payment", role="Booking Agent", parameters=["flight_id", "fare", "traveller"]), Endpoint(method="POST", path="/api/travel/bookings/{booking_id}/cancel", workflow="Cancellation & Refund", role="Booking Agent", parameters=["booking_id"]), Endpoint(method="POST", path="/api/travel/bookings/{booking_id}/refund", workflow="Cancellation → Refund", role="Agency Admin", parameters=["booking_id"]), Endpoint(method="GET", path="/api/travel/users", workflow="Agency Administration", role="Agency Admin", parameters=[])])
    db.add_all([
        WorkflowGraph(name="Search & Booking",nodes=["Flight search","Booking","Payment"],edges=[["Flight search","Booking"],["Booking","Payment"]],endpoint_refs=["GET /api/travel/flights","POST /api/travel/bookings","GET /api/travel/bookings/{booking_id}"],business_criticality="High"),
        WorkflowGraph(name="Cancellation & Refund",nodes=["Booking","Cancellation","Refund"],edges=[["Booking","Cancellation"],["Cancellation","Refund"]],endpoint_refs=["GET /api/travel/bookings/{booking_id}","POST /api/travel/bookings/{booking_id}/cancel","POST /api/travel/bookings/{booking_id}/refund"],business_criticality="Critical"),
        WorkflowGraph(name="Agency Administration",nodes=["Authentication","Role management"],edges=[["Authentication","Role management"]],endpoint_refs=["GET /api/travel/users"],business_criticality="High"),
    ])
    for role, action, decision, confidence, source in [
        ("Agency Admin","View own agency bookings","Allowed",1.0,"Seeded ground truth"),("Booking Agent","View own agency bookings","Allowed",1.0,"Seeded ground truth"),
        ("Agency Admin","View another agency bookings","Denied",1.0,"Seeded ground truth"),("Booking Agent","View another agency bookings","Denied",1.0,"Seeded ground truth"),
        ("Agency Admin","Manage agency users","Allowed",1.0,"Seeded ground truth"),("Booking Agent","Manage agency users","Denied",1.0,"Seeded ground truth"),
        ("Agency Admin","Modify platform settings","Review",0.62,"Inferred; human review required"),("Booking Agent","Modify platform settings","Denied",1.0,"Seeded ground truth")]:
        db.add(AuthorizationPolicy(role=role,action=action,decision=decision,confidence=confidence,source=source))
    for i, (method, path, workflow, role) in enumerate([("GET","/api/travel/health","Platform","Public"),("GET","/api/travel/bookings/{booking_id}/legacy","Legacy booking lookup","Booking Agent")]):
        db.add(Endpoint(id=100+i, method=method, path=path, workflow=workflow, role=role, classification="Zombie"))
    db.add_all([Event(category="SUCCESS", message="Demo workspace seeded with two agencies, four synthetic users and six API routes."), Event(category="INFO", message="Seeded 60 days of synthetic API observations for inventory classification.")])
    db.commit()


def run_migrations():
    Base.metadata.create_all(engine)
    finding_columns={column["name"] for column in inspect(engine).get_columns("findings")}
    if "risk_factors" not in finding_columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE findings ADD COLUMN risk_factors JSON"))
    with SessionLocal() as db:
        for version in ("0001_initial_schema","0002_finding_risk_factors","0003_agent_attack_plans"):
            if not db.get(SchemaMigration,version): db.add(SchemaMigration(version=version))
        db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    run_migrations()
    with SessionLocal() as db: seed(db)
    yield


app = FastAPI(title="SentinelAI", version="1.0.0", description="Local, controlled DAST demonstration platform", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(","), allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def current_user(request: Request, db: Session = Depends(db_session)) -> User:
    auth = request.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ")
    if not token or token == auth: raise HTTPException(401, "Sign in to continue")
    user = db.get(User, decode_token(token))
    if not user: raise HTTPException(401, "Session user no longer exists")
    return user


def config(db: Session, key: str) -> str:
    row = db.get(DemoConfig, key); return row.value if row else "secure"


def event(db: Session, message: str, category="INFO", scan_id=None):
    db.add(Event(category=category, message=message, scan_id=scan_id)); db.commit()


def serialize(model: Any) -> dict:
    out = {c.name: getattr(model, c.name) for c in model.__table__.columns}
    for key, val in out.items():
        if isinstance(val, datetime): out[key] = val.isoformat()
    return out


class LoginInput(BaseModel):
    email: str
    password: str

class BookingInput(BaseModel):
    flight_id: int
    traveller: str = Field(min_length=2, max_length=120)
    fare: float = Field(gt=0)

class BookingUpdate(BaseModel):
    traveller: str = Field(min_length=2, max_length=120)

class PaymentInput(BaseModel):
    booking_id: int

class UserInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=160)
    role: str = Field(pattern="^(Agency Admin|Booking Agent)$")
    password: str = Field(min_length=8, max_length=80)

class ToggleInput(BaseModel):
    vulnerable: bool


@app.get("/api/health")
def health(): return {"status":"healthy", "service":"SentinelAI API", "target":"TravelCore local demo"}


@app.post("/api/auth/login")
def login(body: LoginInput, db: Session = Depends(db_session)):
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if not user or not verify_password(body.password,user.password_hash): raise HTTPException(401, "Email or password is incorrect")
    return {"token":make_token(user), "user":{"id":user.id,"name":user.name,"email":user.email,"role":user.role,"agency_id":user.agency_id}}


@app.get("/api/auth/me")
def me(user: User = Depends(current_user)):
    return {"id":user.id,"name":user.name,"email":user.email,"role":user.role,"agency_id":user.agency_id}


@app.get("/api/dashboard")
def dashboard(db: Session = Depends(db_session), user: User = Depends(current_user)):
    findings = db.scalars(select(Finding).order_by(Finding.created_at.desc())).all()
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(8)).all()
    eps = db.scalars(select(Endpoint)).all()
    events = db.scalars(select(Event).order_by(Event.created_at.desc()).limit(8)).all()
    return {"metrics":{"apis":len(eps),"active_apis":sum(e.classification=="Active" for e in eps),"zombie_apis":sum(e.classification=="Zombie" for e in eps),"shadow_apis":sum(e.classification=="Shadow" for e in eps),"scans":db.query(Scan).count(),"verified":sum(f.status in ("Verified","Resolved") for f in findings),"high_risk":sum(f.severity in ("Critical","High") and f.status!="Resolved" for f in findings),"resolved":sum(f.status=="Resolved" for f in findings),"health":"Healthy"},"severity":[{"name":s,"value":sum(f.severity==s and f.status!="Resolved" for f in findings)} for s in ["Critical","High","Medium","Low"]],"findings":[serialize(f) for f in findings[:5]],"scans":[serialize(s) for s in scans],"events":[serialize(e) for e in events],"user":user.name}


@app.get("/api/travel/flights")
def flights(origin: str | None = None, destination: str | None = None, db: Session = Depends(db_session), user: User = Depends(current_user)):
    rows = db.scalars(select(Flight)).all()
    return [serialize(f) for f in rows if (not origin or origin.lower() in f.origin.lower()) and (not destination or destination.lower() in f.destination.lower())]


@app.get("/api/travel/flights/{flight_id}")
def flight_detail(flight_id: int, db: Session=Depends(db_session), user: User=Depends(current_user)):
    row=db.get(Flight,flight_id)
    if not row: raise HTTPException(404,"Flight not found")
    return serialize(row)


@app.get("/api/travel/health")
def travel_health(): return {"status":"healthy","application":"TravelCore demo"}


@app.get("/api/travel/bookings")
def bookings(db: Session = Depends(db_session), user: User = Depends(current_user)):
    rows = db.scalars(select(Booking).where(Booking.agency_id == user.agency_id).order_by(Booking.id.desc())).all()
    return [serialize(b) for b in rows]


@app.get("/api/travel/bookings/{booking_id}")
def booking_detail(booking_id: int, db: Session = Depends(db_session), user: User = Depends(current_user)):
    row = db.get(Booking, booking_id)
    if not row: raise HTTPException(404, "Booking not found")
    if row.agency_id != user.agency_id and config(db, "idor") != "vulnerable": raise HTTPException(403, "Booking belongs to another agency")
    return serialize(row)


@app.get("/api/travel/bookings/{booking_id}/legacy")
def legacy_booking(booking_id: int, db: Session=Depends(db_session), user: User=Depends(current_user)):
    raise HTTPException(410,"Legacy booking route has been retired")


@app.put("/api/travel/bookings/{booking_id}")
def update_booking(booking_id: int, body: BookingUpdate, db: Session=Depends(db_session), user: User=Depends(current_user)):
    row=db.get(Booking,booking_id)
    if not row or row.agency_id!=user.agency_id: raise HTTPException(404,"Booking not found")
    if row.status!="confirmed": raise HTTPException(409,"Only confirmed bookings can be updated")
    row.traveller=body.traveller; db.commit(); db.refresh(row); return serialize(row)


@app.post("/api/travel/bookings")
def create_booking(body: BookingInput, db: Session = Depends(db_session), user: User = Depends(current_user)):
    flight = db.get(Flight, body.flight_id)
    if not flight: raise HTTPException(404, "Flight not found")
    amount = body.fare if config(db, "fare") == "vulnerable" else flight.price
    row = Booking(reference="TC-"+secrets.token_hex(4).upper(), agency_id=user.agency_id, user_id=user.id, flight_id=flight.id, traveller=body.traveller, amount=amount, status="confirmed")
    db.add(row); db.flush(); db.add(Ledger(booking_id=row.id, kind="payment", amount=amount, reference=f"PAY-{row.id}")); db.commit(); db.refresh(row)
    return serialize(row)


@app.post("/api/travel/bookings/{booking_id}/cancel")
def cancel_booking(booking_id: int, db: Session = Depends(db_session), user: User = Depends(current_user)):
    row=db.get(Booking,booking_id)
    if not row or row.agency_id != user.agency_id: raise HTTPException(404,"Booking not found")
    if row.status == "cancelled": raise HTTPException(409,"Booking is already cancelled")
    row.status="cancelled"; db.commit(); return {"status":"cancelled","booking_id":row.id}


@app.post("/api/travel/bookings/{booking_id}/refund")
def refund(booking_id: int, db: Session = Depends(db_session), user: User = Depends(current_user)):
    row=db.get(Booking,booking_id)
    if not row or row.agency_id != user.agency_id: raise HTTPException(404,"Booking not found")
    if row.status != "cancelled": raise HTTPException(409,"Only cancelled bookings can be refunded")
    existing=db.scalar(select(Ledger).where(Ledger.booking_id==row.id, Ledger.kind=="refund").limit(1))
    if existing and config(db,"refund") != "vulnerable": raise HTTPException(409,"Refund already issued for this booking")
    entry=Ledger(booking_id=row.id,kind="refund",amount=row.amount,reference=f"REF-{row.id}-{secrets.token_hex(3)}")
    db.add(entry); db.commit(); return {"status":"processed","booking_id":row.id,"refund_amount":entry.amount,"refund_id":entry.id}


@app.get("/api/travel/bookings/{booking_id}/refund")
def refund_status(booking_id: int, db: Session=Depends(db_session), user: User=Depends(current_user)):
    row=db.get(Booking,booking_id)
    if not row or row.agency_id!=user.agency_id: raise HTTPException(404,"Booking not found")
    entries=db.scalars(select(Ledger).where(Ledger.booking_id==row.id,Ledger.kind=="refund").order_by(Ledger.id)).all()
    return {"booking_id":row.id,"status":"processed" if entries else "not_requested","refunds":[serialize(x) for x in entries]}


@app.get("/api/travel/payments")
def payments(db: Session = Depends(db_session), user: User = Depends(current_user)):
    rows=db.scalars(select(Ledger).join(Booking).where(Booking.agency_id==user.agency_id).order_by(Ledger.id.desc())).all()
    return [serialize(x) for x in rows]


@app.post("/api/travel/payments")
def simulate_payment(body: PaymentInput, db: Session=Depends(db_session), user: User=Depends(current_user)):
    row=db.get(Booking,body.booking_id)
    if not row or row.agency_id!=user.agency_id: raise HTTPException(404,"Booking not found")
    if row.status!="confirmed": raise HTTPException(409,"Payment requires a confirmed booking")
    existing=db.scalar(select(Ledger).where(Ledger.booking_id==row.id,Ledger.kind=="payment").limit(1))
    if existing: raise HTTPException(409,"Payment already simulated for this booking")
    payment=Ledger(booking_id=row.id,kind="payment",amount=row.amount,reference=f"PAY-{row.id}-{secrets.token_hex(3)}")
    db.add(payment); db.commit(); db.refresh(payment); return serialize(payment)


@app.get("/api/travel/users")
def agency_users(db: Session = Depends(db_session), user: User = Depends(current_user), db2: Session = Depends(db_session)):
    if user.role != "Agency Admin": raise HTTPException(403,"Agency Admin role required")
    return [{"id":u.id,"name":u.name,"email":u.email,"role":u.role,"agency_id":u.agency_id} for u in db2.scalars(select(User).where(User.agency_id==user.agency_id)).all()]


def safety_request(db: Session, *, target: str, principal: str, purpose: str, operation: str, approved_account: bool=True):
    host=urlparse(target).hostname
    account=db.scalar(select(User).where(User.email==principal))
    approved_account=approved_account and bool(account)
    if host not in DEMO_HOST_ALLOWLIST: outcome="BLOCKED_SCOPE"; allowed=False
    elif not approved_account: outcome="BLOCKED_ACCOUNT"; allowed=False
    elif operation not in {"read_booking","test_fare","test_refund","health","login"}: outcome="BLOCKED_OPERATION"; allowed=False
    elif db.query(Audit).filter(Audit.created_at > datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(seconds=60), Audit.principal==principal).count() >= 120: outcome="RATE_LIMITED"; allowed=False
    else: outcome="ALLOWED"; allowed=True
    db.add(Audit(principal=principal,method="HTTP",target=target,purpose=purpose,outcome=outcome)); db.commit()
    if not allowed: raise HTTPException(403, f"Safety layer blocked request: {outcome}")


def request_client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://travelcore.local", timeout=3.0, follow_redirects=False)


async def checked_request(db: Session, client: httpx.AsyncClient, *, path: str, principal: str, purpose: str, operation: str, headers: dict | None = None, json_body: dict | None = None):
    target="http://travelcore.local"+path
    safety_request(db,target=target,principal=principal,purpose=purpose,operation=operation)
    safety_request(db,target="http://travelcore.local/api/health",principal=principal,purpose=purpose+" health check",operation="health")
    health=await client.get("/api/health")
    if health.status_code!=200 or health.json().get("status")!="healthy": raise RuntimeError("Target health check failed; scan stopped")
    if json_body is None:
        return await client.request("GET",path,headers=headers)
    return await client.request("POST",path,headers=headers,json=json_body)


def get_config_map(db: Session): return {x.key:x.value for x in db.scalars(select(DemoConfig)).all()}


def finding_data(scenario: str, evidence: dict):
    specs={
        "idor":("Cross-agency booking disclosure","Broken access control","High","A user from Meridian Journeys can view a Northstar booking, exposing traveller and itinerary data across agency boundaries.","The booking lookup checks that a record exists but, in vulnerable mode, omits the agency ownership check.","Validate booking.agency_id against the authenticated principal's agency on every object lookup.","Assert agency A receives 403 or 404 for an agency B booking; assert own-agency access remains 200.","Booking & Authorization"),
        "fare":("Client-controlled booking fare","Business logic","High","A manipulated fare creates an underpriced booking and synthetic payment entry.","The booking endpoint trusts the fare sent by the client instead of using the server's flight price.","Load the selected flight server-side and calculate the payable fare from trusted pricing data.","Submit a fare below the catalog fare and assert the stored booking and payment equal the server price.","Search → Booking → Payment"),
        "refund":("Duplicate refund processed","Business logic","Critical","Repeated refund requests create multiple synthetic credits for one cancelled booking.","The refund flow does not enforce a single refund state or idempotency key.","Enforce a unique refund per booking and use an idempotent transaction key in the same database transaction.","Submit two refunds for one cancelled booking and assert exactly one ledger refund exists.","Cancellation → Refund"),
    }
    title,cat,severity,impact,explanation,fix,test,workflow=specs[scenario]
    factors={"technical_severity":25 if severity=="Critical" else 20,"data_sensitivity":20 if scenario=="idor" else 12 if scenario=="refund" else 8,"financial_impact":20 if scenario=="refund" else 18 if scenario=="fare" else 2,"cross_agency_exposure":10 if scenario=="idor" else 0,"workflow_reach":10 if scenario=="refund" else 9 if scenario=="fare" else 8,"exploitability":5,"verification_confidence":10}
    return dict(title=title,category=cat,severity=severity,endpoint={"idor":"GET /api/travel/bookings/{booking_id}","fare":"POST /api/travel/bookings","refund":"POST /api/travel/bookings/{booking_id}/refund"}[scenario],agency="Cross-agency" if scenario=="idor" else "Northstar Travel",confidence=0.99,business_impact=impact,explanation=explanation,evidence=evidence,risk_factors=factors,remediation=fix,regression_test=test,workflow=workflow)


async def run_scan(scan_id: int, scenario: str, retest: bool=False):
    with SessionLocal() as db:
        scan=db.get(Scan,scan_id); scan.status="Running"; scan.progress=5; db.commit()
        try:
            target="http://travelcore.local"; headers={"authorization":"Bearer "+make_token(db.get(User,2))}; admin_headers={"authorization":"Bearer "+make_token(db.get(User,1))}
            agent="agent@northstar.demo"; admin="admin@northstar.demo"; evidence={}; event(db,"Recon mapped the changed endpoint to the "+scenario+" workflow.","INFO",scan_id)
            plan=create_plan(scenario)
            db.add(AttackPlan(scan_id=scan_id,scenario=scenario,endpoint=plan["endpoint"],category=plan["category"],reason=plan["reason"],principal=plan["principal"],preconditions=plan["preconditions"],procedure=plan["procedure"],expected_result=plan["expected"],verification_criteria=plan["verification"],risk_level=plan["risk"],approval_required=plan["approval_required"],workflow=plan["workflow"]))
            db.commit()
            event(db,"Planner selected a bounded "+scenario+" proof using approved synthetic accounts.","INFO",scan_id)
            scan.progress=25; db.commit()
            async with request_client() as client:
                if scenario=="idor":
                    own=await checked_request(db,client,path="/api/travel/bookings/101",principal=agent,purpose=f"scan:{scan_id} own-agency authorization control",operation="read_booking",headers=headers)
                    result=await checked_request(db,client,path="/api/travel/bookings/202",principal=agent,purpose=f"scan:{scan_id} cross-agency authorization proof",operation="read_booking",headers=headers)
                    evidence={"own_agency_status":own.status_code,"cross_agency_status":result.status_code,"foreign_booking_returned":result.status_code==200,"resource":"booking 202 (Meridian synthetic record)"}
                    vulnerable=result.status_code==200
                elif scenario=="fare":
                    r=await checked_request(db,client,path="/api/travel/bookings",principal=agent,purpose=f"scan:{scan_id} client fare integrity proof",operation="test_fare",headers=headers,json_body={"flight_id":1,"traveller":"Synthetic DAST Traveller","fare":1})
                    data=r.json() if r.status_code==200 else {"error":r.text}
                    evidence={"catalog_fare":12000,"submitted_fare":1,"accepted_fare":data.get("amount"),"http_status":r.status_code}
                    vulnerable=r.status_code==200 and data.get("amount",12000)<12000
                else:
                    # Use a fresh synthetic booking and cancel it before exercising the duplicate path.
                    created=await checked_request(db,client,path="/api/travel/bookings",principal=agent,purpose=f"scan:{scan_id} create synthetic refund precondition",operation="test_refund",headers=headers,json_body={"flight_id":3,"traveller":"Synthetic Refund Traveller","fare":6700})
                    booking=created.json(); bid=booking.get("id")
                    await checked_request(db,client,path=f"/api/travel/bookings/{bid}/cancel",principal=agent,purpose=f"scan:{scan_id} cancel synthetic refund booking",operation="test_refund",headers=headers,json_body={})
                    first=await checked_request(db,client,path=f"/api/travel/bookings/{bid}/refund",principal=admin,purpose=f"scan:{scan_id} first synthetic refund request",operation="test_refund",headers=admin_headers,json_body={})
                    second=await checked_request(db,client,path=f"/api/travel/bookings/{bid}/refund",principal=admin,purpose=f"scan:{scan_id} duplicate synthetic refund proof",operation="test_refund",headers=admin_headers,json_body={})
                    count=len(db.scalars(select(Ledger).where(Ledger.booking_id==bid,Ledger.kind=="refund")).all())
                    evidence={"booking_id":bid,"first_status":first.status_code,"second_status":second.status_code,"refund_ledger_entries":count,"synthetic_refund_total":count*6700}
                    vulnerable=count>1
            scan.progress=65; db.commit(); event(db,"Controlled proof completed; independent verifier is checking observable application state.","INFO",scan_id)
            # Verifier uses the response and ledger state, independent from the planner recommendation.
            verified=bool(vulnerable)
            scan.progress=90; db.commit()
            title_filter={"idor":"Cross-agency booking disclosure","fare":"Client-controlled booking fare","refund":"Duplicate refund processed"}[scenario]
            previous=db.scalars(select(Finding).where(Finding.title==title_filter,Finding.status.in_(["Resolved","Verified","Reopened"])).order_by(Finding.created_at.desc())).first()
            if retest and previous:
                status="Reopened" if verified else "Resolved"
                previous.status=status
                evidence["retest"]="Proof reproduced; finding reopened" if verified else "Secure response verified; finding resolved"
                finding=previous
                db.add(RetestRun(finding_id=previous.id,scan_id=scan_id,result=status,evidence=evidence))
            elif verified:
                data=finding_data(scenario,evidence); finding=Finding(scan_id=scan_id,**data); db.add(finding); status="Verified"
            else: status="Secure"
            scan.status="Completed"; scan.progress=100; scan.risk_score=sum(data["risk_factors"].values()) if verified and not retest else sum(finding_data(scenario,evidence)["risk_factors"].values()) if verified else 0
            db.commit()
            event(db,"Independent verification confirmed the vulnerability." if verified else "Independent verification confirmed the secure behavior.","SECURITY" if verified else "SUCCESS",scan_id)
            if verified: event(db,"Evidence-backed finding and endpoint-specific remediation are ready.","WARNING",scan_id)
            return {"scan_id":scan_id,"status":scan.status,"scenario":scenario,"verified":verified,"finding_id":finding.id if verified else (previous.id if retest and previous else None),"finding_status":status,"evidence":evidence}
        except Exception as exc:
            scan.status="Failed"; db.commit(); event(db,f"Scan stopped safely: {str(exc)[:180]}","ERROR",scan_id); raise


@app.get("/api/endpoints")
def endpoints(search: str="", db: Session=Depends(db_session), user: User=Depends(current_user)):
    rows=db.scalars(select(Endpoint).order_by(Endpoint.id)).all()
    return [serialize(e) for e in rows if search.lower() in (e.path+e.method+e.workflow).lower()]


@app.get("/api/workflows")
def workflows(db: Session=Depends(db_session), user: User=Depends(current_user)):
    rows=db.scalars(select(WorkflowGraph).order_by(WorkflowGraph.id)).all()
    return [{"id":w.id,"name":w.name,"nodes":w.nodes,"edges":w.edges,"endpoint_refs":w.endpoint_refs,"business_criticality":w.business_criticality} for w in rows]


@app.get("/api/findings")
def findings(status: str="", severity: str="", db: Session=Depends(db_session), user: User=Depends(current_user)):
    rows=db.scalars(select(Finding).order_by(Finding.created_at.desc())).all()
    return [serialize(f) for f in rows if (not status or f.status==status) and (not severity or f.severity==severity)]


@app.get("/api/findings/{finding_id}")
def finding(finding_id: int, db: Session=Depends(db_session), user: User=Depends(current_user)):
    row=db.get(Finding,finding_id)
    if not row: raise HTTPException(404,"Finding not found")
    return serialize(row)


@app.post("/api/scans")
async def create_scan(body: dict, db: Session=Depends(db_session), user: User=Depends(current_user)):
    scenario=body.get("scenario","idor")
    if scenario not in {"idor","fare","refund"}: raise HTTPException(422,"Choose one of the supported demo scenarios")
    row=Scan(scenario=scenario,version=config(db,"version"),status="Queued"); db.add(row); db.commit(); db.refresh(row)
    event(db,"Scan queued for "+scenario+" with local target allowlist enforced.","INFO",row.id)
    return await run_scan(row.id,scenario)


@app.get("/api/scans")
def scans(db: Session=Depends(db_session), user: User=Depends(current_user)):
    return [serialize(s) for s in db.scalars(select(Scan).order_by(Scan.created_at.desc())).all()]


@app.get("/api/attack-plans")
def attack_plans(db: Session=Depends(db_session), user: User=Depends(current_user)):
    return [serialize(p) for p in db.scalars(select(AttackPlan).order_by(AttackPlan.created_at.desc())).all()]


@app.post("/api/demo/toggle/{scenario}")
def toggle(scenario: str, body: ToggleInput, db: Session=Depends(db_session), user: User=Depends(current_user)):
    if scenario not in {"idor","fare","refund"}: raise HTTPException(404,"Unknown demo scenario")
    row=db.get(DemoConfig,scenario); row.value="vulnerable" if body.vulnerable else "secure"; db.commit()
    event(db,f"Demo control set {scenario} to {row.value}.","WARNING" if body.vulnerable else "SUCCESS")
    return {"scenario":scenario,"mode":row.value}


@app.post("/api/demo/reset")
def reset(db: Session=Depends(db_session), user: User=Depends(current_user)):
    for key in ("idor","fare","refund"):
        row=db.get(DemoConfig,key); row.value="secure"
    for row in db.scalars(select(Ledger).where(Ledger.id>1)).all(): db.delete(row)
    for row in db.scalars(select(Booking).where(Booking.id>303)).all(): db.delete(row)
    for row in db.scalars(select(RetestRun)).all(): db.delete(row)
    for row in db.scalars(select(AttackPlan)).all(): db.delete(row)
    for row in db.scalars(select(Finding)).all(): db.delete(row)
    for row in db.scalars(select(Scan)).all(): db.delete(row)
    db.commit(); event(db,"Demo reset to the known secure baseline.","SUCCESS")
    return {"status":"reset","modes":{"idor":"secure","fare":"secure","refund":"secure"}}


@app.post("/api/deployments")
def deployment(body: dict, db: Session=Depends(db_session), user: User=Depends(current_user)):
    scenario=body.get("scenario","idor")
    old=config(db,"version"); n=int(old.rsplit(".",1)[-1])+1 if old.rsplit(".",1)[-1].isdigit() else 2
    new=f"v1.0.{n}"; db.get(DemoConfig,"version").value=new
    path={"idor":"GET /api/travel/bookings/{booking_id}","fare":"POST /api/travel/bookings","refund":"POST /api/travel/bookings/{booking_id}/refund"}.get(scenario,"POST /api/travel/payments")
    row=Deployment(version=new,scenario=scenario,changes=[{"endpoint":path,"change":"Business logic configuration updated","workflows":["Booking","Payment","Cancellation","Refund"] if scenario in ("fare","refund") else ["Booking & Authorization"],"priority":"High"}]); db.add(row); db.commit(); db.refresh(row)
    event(db,f"Deployment {new} detected. Change impact mapped {path} to connected workflows.","WARNING")
    return serialize(row)


@app.get("/api/deployments")
def deployments(db: Session=Depends(db_session), user: User=Depends(current_user)):
    return [serialize(d) for d in db.scalars(select(Deployment).order_by(Deployment.created_at.desc())).all()]


@app.get("/api/events")
def events(limit: int=Query(80,le=300), db: Session=Depends(db_session), user: User=Depends(current_user)):
    return [serialize(e) for e in db.scalars(select(Event).order_by(Event.created_at.desc()).limit(limit)).all()]


@app.get("/api/events/stream")
async def event_stream(request: Request):
    auth=request.query_params.get("token",""); decode_token(auth)
    async def gen():
        last=0
        for _ in range(90):
            if await request.is_disconnected(): break
            with SessionLocal() as db:
                rows=db.scalars(select(Event).where(Event.id>last).order_by(Event.id).limit(50)).all()
                for row in rows:
                    last=row.id; yield "data: "+json.dumps(serialize(row))+"\n\n"
            await asyncio.sleep(1)
    return StreamingResponse(gen(),media_type="text/event-stream")


@app.get("/api/audit-logs")
def audit_logs(db: Session=Depends(db_session), user: User=Depends(current_user)):
    return [serialize(a) for a in db.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(200)).all()]


@app.get("/api/authorization-intelligence")
def authorization(db: Session=Depends(db_session), user: User=Depends(current_user)):
    policies=db.scalars(select(AuthorizationPolicy).order_by(AuthorizationPolicy.id)).all()
    matrix=[]
    for action in dict.fromkeys(p.action for p in policies):
        admin=next((p for p in policies if p.role=="Agency Admin" and p.action==action),None); agent=next((p for p in policies if p.role=="Booking Agent" and p.action==action),None)
        source=(admin or agent).source if (admin or agent) else "Unknown"
        matrix.append({"action":action,"admin":admin.decision if admin else "Review","agent":agent.decision if agent else "Review","confidence":min(admin.confidence if admin else 0,agent.confidence if agent else 0),"source":source})
    deviations=[]
    if config(db,"idor")=="vulnerable": deviations.append({"action":"View another agency's bookings","observed":"Allowed","expected":"Denied","status":"Verified deviation"})
    return {"matrix":matrix,"deviations":deviations}


@app.get("/api/change-impact")
def change_impact(db: Session=Depends(db_session), user: User=Depends(current_user)):
    dep=db.scalars(select(Deployment).order_by(Deployment.created_at.desc()).limit(1)).first()
    if not dep:return {"deployment":None,"impacts":[]}
    selected_names={"idor":["Search & Booking","Agency Administration"],"fare":["Search & Booking","Cancellation & Refund"],"refund":["Cancellation & Refund"]}.get(dep.scenario,[])
    graph=db.scalars(select(WorkflowGraph).where(WorkflowGraph.name.in_(selected_names))).all()
    refs=list(dict.fromkeys(ref for w in graph for ref in w.endpoint_refs))
    workflows_list=list(dict.fromkeys(w.name for w in graph))
    criticality="Critical" if any(w.business_criticality=="Critical" for w in graph) else "High"
    tests={"idor":["Cross-agency ownership boundary","Role boundary"],"fare":["Fare integrity","Payment ledger consistency","Refund idempotency"],"refund":["Cancelled-state precondition","Refund idempotency"]}.get(dep.scenario,["Authorization boundary","Business logic"])
    return {"deployment":serialize(dep),"impacts":[{"endpoint":c["endpoint"],"workflows":workflows_list,"connected_endpoints":refs,"tests":tests,"business_criticality":criticality,"priority_score":92 if criticality=="Critical" else 82} for c in dep.changes]}


@app.get("/api/fix-suggestions")
def fixes(db: Session=Depends(db_session), user: User=Depends(current_user)):
    rows=db.scalars(select(Finding).order_by(Finding.created_at.desc())).all()
    return [{"finding_id":f.id,"title":f.title,"status":"Suggested","remediation":f.remediation,"regression_test":f.regression_test} for f in rows]


@app.post("/api/retests/{finding_id}")
async def retest(finding_id: int, db: Session=Depends(db_session), user: User=Depends(current_user)):
    f=db.get(Finding,finding_id)
    if not f: raise HTTPException(404,"Finding not found")
    title=f.title.lower()
    scenario="idor" if "booking disclosure" in title else "fare" if "fare" in title else "refund"
    row=Scan(scenario=scenario,version=config(db,"version"),status="Queued"); db.add(row); db.commit(); db.refresh(row)
    event(db,f"Retest started for finding #{finding_id}.","INFO",row.id)
    return await run_scan(row.id,scenario,retest=True)


@app.get("/api/retests")
def retest_history(db: Session=Depends(db_session), user: User=Depends(current_user)):
    return [serialize(r) for r in db.scalars(select(RetestRun).order_by(RetestRun.created_at.desc())).all()]


@app.get("/api/reports/{finding_id}.json")
def report_json(finding_id: int, db: Session=Depends(db_session), user: User=Depends(current_user)):
    f=db.get(Finding,finding_id)
    if not f: raise HTTPException(404,"Finding not found")
    return {"report":"SentinelAI Vulnerability Report","generated_at":datetime.now(timezone.utc).isoformat(),"finding":serialize(f)}


@app.get("/api/reports/{finding_id}.pdf")
def report_pdf(finding_id: int, db: Session=Depends(db_session), user: User=Depends(current_user)):
    f=db.get(Finding,finding_id)
    if not f: raise HTTPException(404,"Finding not found")
    from io import BytesIO
    import re
    lines=["SentinelAI Vulnerability Report",f"Finding: {f.title}",f"Severity: {f.severity} | Status: {f.status}",f"Category: {f.category}",f"Endpoint: {f.endpoint}",f"Workflow: {f.workflow}","Business impact:",f.business_impact,"Root cause:",f.explanation,"Recommended remediation:",f.remediation,"Regression test:",f.regression_test,"Evidence:",json.dumps(f.evidence,ensure_ascii=True)]
    wrapped=[]
    for line in lines:
        raw=line.encode("ascii","replace").decode("ascii")
        wrapped.extend([raw[i:i+92] for i in range(0,max(1,len(raw)),92)])
    commands=["BT","/F1 16 Tf","48 790 Td",f"({wrapped[0]}) Tj","/F1 9 Tf"]
    for line in wrapped[1:]:
        safe_line=line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        commands.extend(["0 -16 Td", f"({safe_line}) Tj"])
    stream="\n".join(commands+['ET']).encode("ascii")
    objects=[b"<< /Type /Catalog /Pages 2 0 R >>",b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",b"<< /Length "+str(len(stream)).encode()+b" >>\nstream\n"+stream+b"\nendstream"]
    buf=BytesIO(); buf.write(b"%PDF-1.4\n%SentinelAI\n"); offsets=[0]
    for i,obj in enumerate(objects,1): offsets.append(buf.tell());buf.write(f"{i} 0 obj\n".encode());buf.write(obj);buf.write(b"\nendobj\n")
    xref=buf.tell();buf.write(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for off in offsets[1:]:buf.write(f"{off:010d} 00000 n \n".encode())
    buf.write(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode());buf.seek(0)
    return StreamingResponse(buf,media_type="application/pdf",headers={"Content-Disposition":f"attachment; filename=sentinelai-finding-{finding_id}.pdf"})


@app.get("/api/settings")
def settings(db: Session=Depends(db_session), user: User=Depends(current_user)):
    return {"target_allowlist":sorted(DEMO_HOST_ALLOWLIST),"request_rate_limit_per_minute":120,"request_timeout_seconds":3,"llm_configured":bool(os.getenv("LLM_API_KEY")),"llm_mode":"Configured" if os.getenv("LLM_API_KEY") else "Deterministic fallback","test_accounts":[{"email":u.email,"role":u.role,"agency_id":u.agency_id} for u in db.scalars(select(User)).all()],"health":"Healthy"}


@app.get("/api/demo/state")
def demo_state(db: Session=Depends(db_session), user: User=Depends(current_user)):
    return {"modes":get_config_map(db),"health":"Healthy","target":"TravelCore local demo","allowlisted":True}


@app.get("/api/travel/team")
def travel_team(db: Session=Depends(db_session), user: User=Depends(current_user)):
    if user.role!="Agency Admin": raise HTTPException(403,"Agency Admin role required")
    return [{"id":u.id,"name":u.name,"email":u.email,"role":u.role,"agency_id":u.agency_id} for u in db.scalars(select(User).where(User.agency_id==user.agency_id)).all()]


@app.post("/api/travel/team")
def create_team_user(body: UserInput, db: Session=Depends(db_session), user: User=Depends(current_user)):
    if user.role!="Agency Admin": raise HTTPException(403,"Agency Admin role required")
    email=body.email.lower().strip()
    if "@" not in email or "." not in email.split("@")[-1]: raise HTTPException(422,"Enter a valid email address")
    if db.scalar(select(User.id).where(User.email==email)): raise HTTPException(409,"Email already exists")
    row=User(email=email,name=body.name.strip(),role=body.role,agency_id=user.agency_id,password_hash=pwd_hash(body.password)); db.add(row); db.commit(); db.refresh(row)
    return {"id":row.id,"email":row.email,"name":row.name,"role":row.role,"agency_id":row.agency_id}


@app.get("/api/travel/agency")
def travel_agency(db: Session=Depends(db_session), user: User=Depends(current_user), db2: Session=Depends(db_session)):
    agency=db2.get(Agency,user.agency_id)
    return {"id":agency.id,"name":agency.name,"current_user":user.name,"role":user.role}


from pathlib import Path
STATIC_DIR=Path(__file__).parent/"static"
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="web")

