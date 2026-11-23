"""Build a cleaned labeled URL CSV from public feeds. Never visits URLs in the feed."""
import csv, io, zipfile
from pathlib import Path
from urllib.request import Request, urlopen
ROOT=Path(__file__).resolve().parent; DATA=ROOT/"data"; OUT=DATA/"training_urls.csv"
URLHAUS="https://urlhaus.abuse.ch/downloads/csv/"
TRANCO="https://tranco-list.eu/top-1m.csv.zip"
def get(url):
 req=Request(url,headers={"User-Agent":"PhishShieldDatasetBuilder/1.0"})
 with urlopen(req,timeout=90) as r:return r.read()
def clean(s):
 s=(s or "").strip().strip('"')
 if not s or len(s)>2048 or any(c.isspace() for c in s):return ""
 if not s.startswith(("http://","https://")):s="https://"+s
 return s
def phishing_rows():
 text=get(URLHAUS).decode("utf-8",errors="replace")
 rows=[]
 reader=csv.reader(line for line in text.splitlines() if line and not line.startswith("#"))
 for r in reader:
  if r:
   u=clean(r[1] if len(r)>1 else r[0])
   if u:rows.append((u,1))
 return rows
def legit_rows(limit=100000):
 archive=zipfile.ZipFile(io.BytesIO(get(TRANCO)))
 name=next(n for n in archive.namelist() if n.lower().endswith(".csv"))
 rows=[]
 with archive.open(name) as f:
  for r in csv.reader(io.TextIOWrapper(f,encoding="utf-8",errors="replace")):
   if not r:continue
   domain=clean(r[1] if len(r)>1 and r[0].isdigit() else r[0])
   if domain:rows.append((domain,0))
   if len(rows)>=limit:break
 return rows
def main():
 DATA.mkdir(parents=True,exist_ok=True)
 print("Downloading public URLhaus phishing feed...")
 bad=phishing_rows(); print("Phishing feed rows:",len(bad))
 print("Downloading Tranco ranking...")
 good=legit_rows()
 seen={}; removed=0
 # Dedupe by normalized URL. Drop conflicting labels rather than silently choosing one.
 for url,label in bad+good:
  key=url.lower().rstrip("/")
  if key in seen:
   if seen[key][1]!=label:seen[key]=None
   removed+=1
  else:seen[key]=(url,label)
 records=[x for x in seen.values() if x]
 with OUT.open("w",newline="",encoding="utf-8") as f:
  w=csv.writer(f);w.writerow(["url","label"]);w.writerows(records)
 print(f"Saved {len(records):,} unique samples; duplicates/conflicts removed: {removed:,}")
 print("Class counts:",sum(y==0 for _,y in records),"legitimate,",sum(y==1 for _,y in records),"phishing")
 print("Sources: URLhaus and Tranco. URL entries are not visited.")
if __name__=="__main__":main()
