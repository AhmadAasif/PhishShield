"""Build cleaned labels from public URLhaus and Tranco files. Does not visit feed URLs."""
import csv,io,zipfile
from pathlib import Path
from urllib.request import Request,urlopen
ROOT=Path(__file__).resolve().parent;DATA=ROOT/"data";OUT=DATA/"training_urls.csv"
URLHAUS="https://urlhaus.abuse.ch/downloads/csv/";TRANCO="https://tranco-list.eu/top-1m.csv.zip"
def get(url):
 req=Request(url,headers={"User-Agent":"PhishShieldDatasetBuilder/1.0"})
 with urlopen(req,timeout=90) as r:return r.read()
def clean(s):
 s=(s or "").strip().strip('"')
 if not s or len(s)>2048 or any(c.isspace() for c in s):return ""
 if not s.startswith(("http://","https://")):s="https://"+s
 return s
def phishing_rows():
 text=get(URLHAUS).decode("utf-8",errors="replace");out=[]
 reader=csv.reader(line for line in text.splitlines() if line and not line.startswith("#"))
 for row in reader:
  if row:
   u=clean(row[1] if len(row)>1 else row[0])
   if u:out.append((u,1))
 return out
def legit_rows(limit=100000):
 z=zipfile.ZipFile(io.BytesIO(get(TRANCO)));name=next(n for n in z.namelist() if n.lower().endswith(".csv"));out=[]
 with z.open(name) as f:
  for row in csv.reader(io.TextIOWrapper(f,encoding="utf-8",errors="replace")):
   if not row:continue
   u=clean(row[1] if len(row)>1 and row[0].isdigit() else row[0])
   if u:out.append((u,0))
   if len(out)>=limit:break
 return out
def main():
 DATA.mkdir(parents=True,exist_ok=True);print("Downloading URLhaus phishing feed...");bad=phishing_rows();print("Phishing feed rows:",len(bad))
 print("Downloading Tranco top-domain archive...");good=legit_rows()
 unique={};conflicts=set();duplicates=0
 for u,y in bad+good:
  key=u.lower().rstrip("/")
  if key in unique:
   duplicates+=1
   if unique[key][1]!=y:conflicts.add(key)
  else:unique[key]=(u,y)
 records=[item for key,item in unique.items() if key not in conflicts]
 with OUT.open("w",newline="",encoding="utf-8") as f:
  w=csv.writer(f);w.writerow(["url","label"]);w.writerows(records)
 print(f"Saved {len(records):,} clean unique URLs; duplicate/conflicting keys removed: {duplicates:,}")
 print(f"Legitimate={sum(y==0 for _,y in records):,}; phishing={sum(y==1 for _,y in records):,}")
 print("Source feeds are downloaded as data. URL entries are not opened.")
if __name__=="__main__":main()
