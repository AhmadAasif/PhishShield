import unittest
from detector import FEATURE_NAMES,extract_features,normalize_url,rule_analysis
class DetectorFeatureTests(unittest.TestCase):
 def test_normalizes_bare_domain(self):
  self.assertEqual(normalize_url("example.org"),"https://example.org")
 def test_feature_vector_matches_expected_names(self):
  features=extract_features("https://example.org/path?a=1")
  self.assertEqual(set(features),set(FEATURE_NAMES))
  self.assertEqual(len(features),27)
 def test_ip_host_triggers_rule(self):
  score,reasons=rule_analysis("http://192.0.2.1/login")
  self.assertGreater(score,0)
  self.assertTrue(any("IP address" in r["message"] for r in reasons))
 def test_rejects_unsupported_scheme(self):
  with self.assertRaises(ValueError):normalize_url("ftp://example.org")
if __name__=="__main__":unittest.main()
