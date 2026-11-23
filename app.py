from flask import Flask,jsonify,render_template,request
import json
from database import clear_history,get_history,get_stats,init_db,save_scan
from detector import PhishingDetector,REPORT_PATH
app=Flask(__name__);app.config["JSON_SORT_KEYS"]=False
init_db();detector=PhishingDetector()
@app.get("/")
def home():return render_template("index.html")
@app.get("/api/history")
def history_api():
 try:limit=int(request.args.get("limit",100))
 except ValueError:limit=100
 query=request.args.get("q","").strip().lower();level=request.args.get("level","").strip()
 items=get_history(limit)
 if query:items=[i for i in items if query in i["url"].lower() or query in i["verdict"].lower()]
 if level:items=[i for i in items if i["level"]==level]
 return jsonify({"history":items,"stats":get_stats()})
@app.get("/api/stats")
def stats_api():return jsonify(get_stats())
@app.get("/api/models")
def models_api():
 if REPORT_PATH.exists():
  try:return jsonify(json.loads(REPORT_PATH.read_text(encoding="utf-8")))
  except (OSError,json.JSONDecodeError):pass
 return jsonify({"available":False,"message":"No evaluation report yet. Download a public dataset and run model training."})
@app.post("/api/scan")
def scan_api():
 data=request.get_json(silent=True) or {};raw=data.get("url","")
 if not isinstance(raw,str):return jsonify({"error":"URL must be text."}),400
 try:
  result=detector.scan(raw);result["id"]=save_scan(result);return jsonify(result)
 except ValueError as e:return jsonify({"error":str(e)}),400
 except Exception:
  app.logger.exception("URL scan failed");return jsonify({"error":"Scan failed. Check server logs."}),500
@app.post("/api/history/clear")
def clear_api():clear_history();return jsonify({"message":"History cleared","stats":get_stats()})
if __name__=="__main__":
 print("\nPhishShield running at http://127.0.0.1:5000\nURL text only; no submitted sites are visited.\n")
 app.run(host="127.0.0.1",port=5000,debug=False)
