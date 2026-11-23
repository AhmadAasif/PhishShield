"""Stratified holdout evaluation and comparison of three URL classifiers."""
import csv,json
from datetime import datetime,timezone
from pathlib import Path
import joblib
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,confusion_matrix
from detector import FEATURE_NAMES,extract_features,normalize_url
ROOT=Path(__file__).resolve().parent; CSV=ROOT/"data"/"training_urls.csv"; MD=ROOT/"model"; REPORT=MD/"evaluation_report.json"
def read_data():
 unique={};invalid=0
 with CSV.open("r",newline="",encoding="utf-8") as f:
  for row in csv.DictReader(f):
   try:
    u=normalize_url(row.get("url","")); y=int(row.get("label",""))
    if y not in (0,1):raise ValueError("label")
    unique.setdefault(u.lower().rstrip("/"),(u,y))
   except (ValueError,TypeError):invalid+=1
 samples=list(unique.values())
 if len(samples)<20 or len({y for _,y in samples})<2:raise RuntimeError("At least 20 clean samples with both labels required. Run dataset_builder.py.")
 X=[[extract_features(u)[n] for n in FEATURE_NAMES] for u,_ in samples]; y=[label for _,label in samples]
 return X,y,invalid
def main():
 MD.mkdir(exist_ok=True);X,y,invalid=read_data()
 Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
 models={"Random Forest":RandomForestClassifier(n_estimators=300,max_depth=18,min_samples_leaf=2,class_weight="balanced",n_jobs=-1,random_state=42),
 "Logistic Regression":make_pipeline(StandardScaler(),LogisticRegression(max_iter=2000,class_weight="balanced",random_state=42)),
 "Decision Tree":DecisionTreeClassifier(max_depth=18,min_samples_leaf=2,class_weight="balanced",random_state=42)}
 metrics={};matrices={};trained={}
 for name,m in models.items():
  m.fit(Xtr,ytr);p=m.predict(Xte);trained[name]=m
  metrics[name]={k:round(float(v),4) for k,v in {"accuracy":accuracy_score(yte,p),"precision":precision_score(yte,p,zero_division=0),"recall":recall_score(yte,p,zero_division=0),"f1":f1_score(yte,p,zero_division=0)}.items()}
  matrices[name]=confusion_matrix(yte,p,labels=[0,1]).tolist()
 best=max(metrics,key=lambda n:(metrics[n]["f1"],metrics[n]["recall"]))
 joblib.dump({"model":trained[best],"sample_count":len(y),"model_name":best,"feature_names":FEATURE_NAMES},MD/"phishshield_model.joblib")
 importance=[]
 if hasattr(trained[best],"feature_importances_"):
  importance=[{"feature":f,"importance":round(float(v),6)} for f,v in zip(FEATURE_NAMES,trained[best].feature_importances_)]
  importance.sort(key=lambda x:x["importance"],reverse=True)
 report={"generated_at":datetime.now(timezone.utc).isoformat(),"dataset_size":len(y),"invalid_rows_removed":invalid,
 "class_counts":{"legitimate":sum(v==0 for v in y),"phishing":sum(v==1)},"split":{"train":len(ytr),"test":len(yte),"train_percent":80,"test_percent":20},
 "models":metrics,"confusion_matrices":matrices,"selected_model":best,"feature_importance":importance,
 "confusion_matrix_labels":["Legitimate","Phishing"],"note":"Metrics come from stratified held-out test data. Dataset source freshness and labeling quality influence performance."}
 REPORT.write_text(json.dumps(report,indent=2),encoding="utf-8")
 print(json.dumps(report,indent=2));print("Selected:",best)
if __name__=="__main__":main()
