from __future__ import annotations
import csv,ipaddress,math
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit
import joblib
from sklearn.ensemble import RandomForestClassifier
BASE=Path(__file__).resolve().parent; DATASET_PATH=BASE/"data"/"training_urls.csv"; MODEL_DIR=BASE/"model"; MODEL_PATH=MODEL_DIR/"phishshield_model.joblib"; REPORT_PATH=MODEL_DIR/"evaluation_report.json"
FEATURE_NAMES=["url_length","hostname_length","path_length","query_length","dot_count","hyphen_count","at_count","question_count","equal_count","percent_count","digit_count","subdomain_count","has_https","has_ip","has_port","has_punycode","has_suspicious_keyword","has_shortener","has_suspicious_tld","has_double_slash_path","brand_in_subdomain","brand_mismatch","encoded_chars","domain_digit_ratio","parameter_count","host_entropy","has_fragment"]
WORDS={"login","signin","verify","verification","secure","account","update","confirm","password","banking","wallet","payment","suspended","unlock","recover","webscr","bonus","prize","gift","claim","invoice","auth","support","alert"}
BRANDS={"paypal","google","microsoft","apple","amazon","netflix","facebook","instagram","sbi","icici","hdfc","axisbank","onlinesbi","flipkart","whatsapp","telegram"}
BAD_TLDS={"zip","top","xyz","click","work","support","country","gq","tk","ml","cf","ga","rest","fit","quest"}
SHORTENERS={"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly","rebrand.ly"}
MULTI={"co.in","com.au","co.uk","org.uk","ac.in","gov.in","net.in","com.br","co.nz","com.sg"}
def normalize_url(raw):
 v=(raw or "").strip()
 if not v:raise ValueError("Please enter a website URL.")
 if len(v)>2048:raise ValueError("URL too long (maximum 2,048 characters).")
 if any(ch.isspace() for ch in v):raise ValueError("URL cannot contain spaces.")
 if "://" not in v:v="https://"+v
 try:p=urlsplit(v);host=p.hostname;_=p.port
 except ValueError:raise ValueError("Malformed URL.")
 if p.scheme.lower() not in {"http","https"} or not host:raise ValueError("Enter a valid HTTP or HTTPS website URL.")
 return v
def registered_domain(host):
 labels=[x for x in host.lower().strip(".").split(".") if x]
 if len(labels)<=2:return host
 last=".".join(labels[-2:])
 return ".".join(labels[-3:]) if last in MULTI and len(labels)>=3 else last
def entropy(s):
 if not s:return 0.0
 c=Counter(s);n=len(s);return -sum((x/n)*math.log2(x/n) for x in c.values())
def extract_features(url):
 p=urlsplit(url);host=(p.hostname or "").lower();path=p.path or "";query=p.query or "";labels=[x for x in host.split(".") if x];reg=registered_domain(host);sub=".".join(labels[:-len(reg.split("."))]) if reg else "";tld=labels[-1] if labels else ""
 try:ipaddress.ip_address(host);ip=1
 except ValueError:ip=0
 try:port=p.port;hasport=int(port is not None and port not in (80,443))
 except ValueError:hasport=1
 digit=sum(c.isdigit() for c in host)
 return {"url_length":len(url),"hostname_length":len(host),"path_length":len(path),"query_length":len(query),"dot_count":url.count("."),"hyphen_count":url.count("-"),"at_count":url.count("@"),"question_count":url.count("?"),"equal_count":url.count("="),"percent_count":url.count("%"),"digit_count":sum(c.isdigit() for c in url),"subdomain_count":max(0,len(labels)-len(reg.split("."))),"has_https":int(p.scheme.lower()=="https"),"has_ip":ip,"has_port":hasport,"has_punycode":int("xn--" in host),"has_suspicious_keyword":int(any(w in url.lower() for w in WORDS)),"has_shortener":int(any(host==s or host.endswith("."+s) for s in SHORTENERS)),"has_suspicious_tld":int(tld in BAD_TLDS),"has_double_slash_path":int("//" in path),"brand_in_subdomain":int(any(b in sub for b in BRANDS)),"brand_mismatch":int(any(b in host for b in BRANDS) and not any(b in reg for b in BRANDS)),"encoded_chars":int("%" in url),"domain_digit_ratio":digit/max(1,len(host)),"parameter_count":len([x for x in query.split("&") if x]),"host_entropy":entropy(host),"has_fragment":int(bool(p.fragment))}
def rule_analysis(url):
 p=urlsplit(url);host=(p.hostname or "").lower();f=extract_features(url);score=0;reasons=[]
 def add(points,msg,feature,detail):
  nonlocal score
  score+=points;reasons.append({"message":msg,"feature":feature,"detail":detail,"points":points})
 if f["has_ip"]:add(25,"IP address is used instead of a domain","IP host",host)
 if f["at_count"]:add(22,"An @ symbol may obscure the actual destination","At symbol","@ present")
 if f["has_punycode"]:add(15,"Encoded domain labels can imitate other domains","Punycode","xn-- label")
 if f["brand_mismatch"]:add(22,"Brand text appears in a different registered domain","Brand mismatch","Brand-like hostname")
 elif f["brand_in_subdomain"]:add(12,"Brand text is present in a subdomain","Brand subdomain","Subdomain brand text")
 if f["has_suspicious_tld"]:add(10,"TLD is frequently seen in suspicious URL samples","TLD",host.split(".")[-1])
 if f["has_shortener"]:add(8,"URL shortening service hides the destination","URL shortener","Shortened host")
 if f["has_suspicious_keyword"]:add(9,"URL contains common credential/payment lure words","Keywords","Suspicious URL words")
 if len(url)>120:add(12,"URL is unusually long","Length",str(len(url))+" characters")
 elif len(url)>75:add(6,"URL is longer than typical addresses","Length",str(len(url))+" characters")
 if f["subdomain_count"]>=3:add(9,"Several nested subdomains are present","Subdomains",str(f["subdomain_count"]))
 if not f["has_https"]:add(5,"URL does not use HTTPS","Scheme","HTTP")
 if f["has_port"]:add(7,"URL specifies a non-standard port","Port",str(p.port))
 if f["hyphen_count"]>=4:add(6,"URL contains many hyphens","Hyphens",str(f["hyphen_count"]))
 if f["encoded_chars"]:add(4,"Percent-encoded characters are present","Encoding","Percent encoding")
 if "//" in (p.path or ""):add(4,"Extra double-slash sequence in path","Path","Double slash")
 return min(score,100),reasons
class PhishingDetector:
 def __init__(self):self.model,self.sample_count,self.model_name=self.load_or_train()
 def load_or_train(self):
  MODEL_DIR.mkdir(parents=True,exist_ok=True)
  if MODEL_PATH.exists():
   try:
    s=joblib.load(MODEL_PATH);return s["model"],s.get("sample_count",0),s.get("model_name","Random Forest")
   except Exception:pass
  if not DATASET_PATH.exists():raise RuntimeError("Training CSV missing: data/training_urls.csv")
  X=[];y=[]
  with DATASET_PATH.open(newline="",encoding="utf-8") as f:
   for r in csv.DictReader(f):
    try:
     u=normalize_url(r["url"]);label=int(r["label"])
     if label in (0,1):X.append([extract_features(u)[n] for n in FEATURE_NAMES]);y.append(label)
    except (ValueError,KeyError):continue
  if len(y)<10 or len(set(y))<2:raise RuntimeError("Training data requires at least 10 valid rows and both labels.")
  m=RandomForestClassifier(n_estimators=200,max_depth=12,class_weight="balanced",random_state=42);m.fit(X,y)
  joblib.dump({"model":m,"sample_count":len(y),"model_name":"Random Forest"},MODEL_PATH);return m,len(y),"Random Forest"
 def scan(self,raw):
  u=normalize_url(raw);features=extract_features(u);row=[[features[n] for n in FEATURE_NAMES]];probs=self.model.predict_proba(row)[0];classes=list(self.model.classes_)
  ml=round(float(probs[classes.index(1)])*100) if 1 in classes else 0
  rule,reasons=rule_analysis(u);risk=max(0,min(100,round(.4*ml+.6*rule)))
  level="high" if risk>=60 else "medium" if risk>=30 else "low";verdict="Likely Phishing" if level=="high" else "Suspicious" if level=="medium" else "Low Risk"
  if not reasons:reasons=[{"message":"No major URL red flags detected by built-in rules.","feature":"Rules","detail":"No rule triggers","points":0}]
  return {"url":u,"verdict":verdict,"level":level,"risk_score":risk,"ml_score":ml,"rule_score":rule,"reasons":reasons,"features":features,"model_name":self.model_name,"disclaimer":"URL-text analysis only. PhishShield does not visit sites, inspect page content, validate certificates or follow redirects. A low score is not proof of safety."}
