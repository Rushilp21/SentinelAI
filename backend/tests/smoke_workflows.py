"""Integration smoke checks for local SentinelAI demo workflows."""
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import httpx
from app.main import app, SessionLocal, seed, run_migrations


async def main():
    run_migrations()
    with SessionLocal() as db:
        seed(db)
    print("database ready", flush=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        assert (await client.get("/api/health")).json()["status"] == "healthy"
        root = await client.get("/")
        assert root.status_code == 200 and "SentinelAI" in root.text
        assert (await client.post("/api/auth/login",json={"email":"admin@northstar.demo","password":"wrong-password"})).status_code==401
        admin = (await client.post("/api/auth/login", json={"email":"admin@northstar.demo", "password":"Sentinel123!"})).json()["token"]
        ah = {"Authorization":f"Bearer {admin}"}
        agent=(await client.post("/api/auth/login",json={"email":"agent@northstar.demo","password":"Sentinel123!"})).json()["token"]
        assert len((await client.get("/api/travel/team",headers=ah)).json())==2
        assert (await client.get("/api/travel/team",headers={"Authorization":f"Bearer {agent}"})).status_code==403
        print("site and auth", flush=True)

        assert (await client.get("/api/travel/bookings/202", headers=ah)).status_code == 403
        await client.post("/api/demo/toggle/idor", headers=ah, json={"vulnerable":True})
        idor = (await client.post("/api/scans", headers=ah, json={"scenario":"idor"})).json()
        assert idor["verified"] and idor["evidence"]["cross_agency_status"] == 200
        plans=(await client.get("/api/attack-plans",headers=ah)).json()
        assert plans and plans[0]["endpoint"]=="GET /api/travel/bookings/{booking_id}" and plans[0]["approval_required"] is False
        finding = (await client.get(f"/api/findings/{idor['finding_id']}", headers=ah)).json()
        await client.post("/api/demo/toggle/idor", headers=ah, json={"vulnerable":False})
        retest = (await client.post(f"/api/retests/{finding['id']}", headers=ah)).json()
        assert not retest["verified"] and retest["finding_status"] == "Resolved"
        print("IDOR and retest", flush=True)

        await client.post("/api/demo/toggle/fare", headers=ah, json={"vulnerable":True})
        fare = (await client.post("/api/scans", headers=ah, json={"scenario":"fare"})).json()
        assert fare["verified"] and fare["evidence"]["accepted_fare"] == 1
        await client.post("/api/demo/toggle/fare", headers=ah, json={"vulnerable":False})
        fare_secure = (await client.post("/api/scans", headers=ah, json={"scenario":"fare"})).json()
        assert not fare_secure["verified"]
        print("fare vulnerable and secure", flush=True)

        await client.post("/api/demo/toggle/refund", headers=ah, json={"vulnerable":True})
        refund = (await client.post("/api/scans", headers=ah, json={"scenario":"refund"})).json()
        assert refund["verified"] and refund["evidence"]["refund_ledger_entries"] == 2
        await client.post("/api/demo/toggle/refund", headers=ah, json={"vulnerable":False})
        refund_secure = (await client.post("/api/scans", headers=ah, json={"scenario":"refund"})).json()
        assert not refund_secure["verified"] and refund_secure["evidence"]["refund_ledger_entries"] == 1
        print("refund vulnerable and secure", flush=True)

        assert len((await client.get("/api/audit-logs", headers=ah)).json()) >= 10
        report = await client.get(f"/api/reports/{finding['id']}.pdf", headers=ah)
        assert report.status_code == 200 and report.content.startswith(b"%PDF-1.4")
        assert (await client.get(f"/api/reports/{finding['id']}.json", headers=ah)).status_code == 200
        assert len((await client.get("/api/workflows",headers=ah)).json()) >= 3
        classifications={x["classification"] for x in (await client.get("/api/endpoints",headers=ah)).json()}
        assert "Active" in classifications and "Zombie" in classifications
        assert (await client.get("/api/change-impact",headers=ah)).status_code == 200
        assert (await client.get("/api/authorization-intelligence",headers=ah)).json()["matrix"]
        await client.post("/api/demo/reset",headers=ah)
        print("PASS: site, auth, three scenarios, independent verification, retest, audit, JSON/PDF reports", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
