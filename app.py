from flask import Flask, jsonify, render_template, request

from database import clear_history, get_history, get_stats, init_db, save_scan
from detector import PhishingDetector

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

init_db()
detector = PhishingDetector()


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/api/history")
def history_api():
    return jsonify({"history": get_history(), "stats": get_stats()})


@app.post("/api/scan")
def scan_api():
    payload = request.get_json(silent=True) or {}
    raw_url = payload.get("url", "")
    if not isinstance(raw_url, str):
        return jsonify({"error": "URL must be text."}), 400

    try:
        result = detector.scan(raw_url)
        scan_id = save_scan(result)
        result["id"] = scan_id
        return jsonify(result)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("URL scan failed")
        return jsonify({"error": "The scan could not be completed. Check the server terminal for details."}), 500


@app.post("/api/history/clear")
def clear_history_api():
    clear_history()
    return jsonify({"message": "Scan history cleared.", "stats": get_stats()})


if __name__ == "__main__":
    print("\nPhishShield is running at http://127.0.0.1:5000")
    print("Educational prototype: it analyses URL text only and never opens submitted websites.\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
