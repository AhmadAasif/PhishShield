# PhishShield 2.0
PhishShield is an educational URL-text phishing screening app combining URL feature extraction, a machine-learning model, transparent rules, and SQLite scan history in a dark analytics dashboard.

**Safety boundary:** submitted URLs are never opened, fetched, crawled or followed. Analysis uses the URL string only. Low risk is not proof of safety.

## Features
- Dashboard statistics, risk distribution and recent scan activity
- URL scan with ML score, rule score, explainable signals and feature details
- Search/filter history
- Public dataset preparation using URLhaus phishing feed and Tranco ranking
- Stratified 80/20 train/test model evaluation for Random Forest, Logistic Regression and Decision Tree
- Accuracy, precision, recall, F1-score and per-model confusion matrices
- Select model by held-out F1, recall as tie-breaker; save model and JSON report

## Install and run
Python 3.10+ recommended. Windows quick-start: double-click `start_windows.bat`. Manual:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Download public dataset and evaluate
Sources:
- URLhaus feed: https://urlhaus.abuse.ch/downloads/csv/
- Tranco top-domain list: https://tranco-list.eu/

Run:
```bash
python dataset_builder.py
python train_models.py
```
One-step:
```bash
python train_model.py --download-dataset
```
The pipeline filters invalid/empty entries, normalizes scheme, deduplicates URL strings and excludes conflicting duplicate labels, validates binary labels, then uses stratified 80% training and 20% testing. Metrics are calculated on the held-out test split. Generated files:
- `model/phishshield_model.joblib` selected model
- `model/evaluation_report.json` dataset statistics, split counts, metrics, confusion matrices and feature importance

Dataset feeds change. Review sources, terms, freshness and labeling quality before formal use. Tranco-ranked domains are assumed legitimate labels but are not ground truth. Feed URLs are treated as data and never opened by PhishShield.

If no trained artifact exists, the app fits a fallback Random Forest using the small demonstration CSV. Run the dataset/training steps above to enable model comparison in Analytics.

## Metric meanings
- Accuracy: fraction of all predictions correct
- Precision: fraction of phishing predictions that are labeled phishing
- Recall: fraction of phishing test URLs detected
- F1: harmonic mean of precision and recall
- Confusion matrix rows = actual (Legitimate, Phishing), columns = predicted (Legitimate, Phishing)

No model performance values are claimed until the training/evaluation script is run on the fetched dataset.

## API
- `GET /` dashboard
- `POST /api/scan` JSON body `{"url":"https://example.com"}`
- `GET /api/history?limit=100&q=&level=` scan history, stats, optional filters
- `GET /api/stats` counters
- `GET /api/models` saved evaluation report
- `POST /api/history/clear` clear records

## Hybrid risk score
40% ML phishing probability + 60% rule score. Score 0–29 Low Risk, 30–59 Suspicious, 60–100 Likely Phishing. These are heuristic thresholds, not calibrated probabilities.

## Limitations
URL-string analysis only; no page content, redirects, DNS, certificates or email inspection. Dataset labels can be noisy; ranked domains can be compromised. False positives and false negatives are possible. Educational prototype, not browser protection.
