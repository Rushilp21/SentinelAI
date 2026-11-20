"""HTTP smoke checks for a running local Uvicorn app (127.0.0.1:8000)."""
import httpx

BASE="http://127.0.0.1:8000"

def main():
    with httpx.Client(base_url=BASE,timeout=10) as client:
        page=client.get("/")
        assert page.status_code==200 and "SentinelAI" in page.text
        assert client.get("/app.js").status_code==200
        assert client.get("/style.css").status_code==200
        auth=client.post("/api/auth/login",json={"email":"admin@northstar.demo","password":"Sentinel123!"})
        assert auth.status_code==200
        client.headers["Authorization"]="Bearer "+auth.json()["token"]
        assert client.get("/api/dashboard").status_code==200
        client.post("/api/demo/toggle/idor",json={"vulnerable":True}).raise_for_status()
        scan=client.post("/api/scans",json={"scenario":"idor"}).json()
        assert scan["verified"] is True
        client.post("/api/demo/toggle/idor",json={"vulnerable":False}).raise_for_status()
        retest=client.post(f"/api/retests/{scan['finding_id']}").json()
        assert retest["finding_status"]=="Resolved"
        client.post("/api/demo/reset").raise_for_status()
    print("PASS: Uvicorn-served homepage/assets, authenticated dashboard, live IDOR scan and secure retest")

if __name__=="__main__": main()
