import unittest
from app import app
from database import clear_history
class FlaskAPITests(unittest.TestCase):
 def setUp(self):
  app.config["TESTING"]=True
  self.client=app.test_client()
  clear_history()
 def tearDown(self):clear_history()
 def test_scan_endpoint_returns_explanation_and_saves_history(self):
  response=self.client.post("/api/scan",json={"url":"example.org"})
  self.assertEqual(response.status_code,200)
  data=response.get_json()
  for key in ("verdict","risk_score","ml_score","rule_score","reasons","features","disclaimer"):
   self.assertIn(key,data)
  history=self.client.get("/api/history").get_json()
  self.assertEqual(history["stats"]["total"],1)
  self.assertEqual(len(history["history"]),1)
 def test_invalid_url_returns_400(self):
  response=self.client.post("/api/scan",json={"url":"ftp://example.org"})
  self.assertEqual(response.status_code,400)
if __name__=="__main__":unittest.main()
