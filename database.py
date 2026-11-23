import json,sqlite3
from datetime import datetime,timezone
from pathlib import Path
BASE_DIR=Path(__file__).resolve().parent; DB_PATH=BASE_DIR/"instance"/"phishshield.db"
def _connect():
 DB_PATH.parent.mkdir(parents=True,exist_ok=True);c=sqlite3.connect(DB_PATH);c.row_factory=sqlite3.Row;return c
def init_db():
 with _connect() as c:
  c.execute("""CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,url TEXT NOT NULL,verdict TEXT NOT NULL,level TEXT NOT NULL,risk_score INTEGER NOT NULL,ml_score INTEGER NOT NULL,rule_score INTEGER NOT NULL,reasons TEXT NOT NULL,scanned_at TEXT NOT NULL)""");c.commit()
def save_scan(r):
 stamp=datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
 with _connect() as c:
  cur=c.execute("INSERT INTO scans(url,verdict,level,risk_score,ml_score,rule_score,reasons,scanned_at) VALUES(?,?,?,?,?,?,?,?)",(r["url"],r["verdict"],r["level"],r["risk_score"],r["ml_score"],r["rule_score"],json.dumps(r["reasons"]),stamp));c.commit();return cur.lastrowid
def get_history(limit=100):
 limit=max(1,min(int(limit),1000))
 with _connect() as c:rows=c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
 result=[]
 for row in rows:
  x=dict(row);x["reasons"]=json.loads(x["reasons"]);result.append(x)
 return result
def get_stats():
 with _connect() as c:
  total=c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
  high=c.execute("SELECT COUNT(*) FROM scans WHERE level='high'").fetchone()[0]
  medium=c.execute("SELECT COUNT(*) FROM scans WHERE level='medium'").fetchone()[0]
  low=c.execute("SELECT COUNT(*) FROM scans WHERE level='low'").fetchone()[0]
 return {"total":total,"phishing_detected":high,"legitimate_detected":low,"suspicious":medium,"risk_distribution":{"high":high,"medium":medium,"low":low}}
def clear_history():
 with _connect() as c:c.execute("DELETE FROM scans");c.commit()
