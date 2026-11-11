# PhishShield
**An Intelligent Machine Learning-Based Phishing URL Detection and Risk Analysis System**

PhishShield is a local Flask web application that analyses URL text and highlights possible phishing indicators. It combines a Random Forest classifier with explainable URL rules and stores scan history in SQLite.

## Features
- URL input and validation
- Feature extraction from URL structure
- Random Forest machine-learning classification
- Explainable URL warning signals
- Combined risk score from 0 to 100
- Low Risk / Suspicious / Likely Phishing result
- SQLite scan history and dashboard statistics
- Runs locally; submitted websites are never opened or fetched

## Requirements
- Python 3.10 or newer
- Internet connection for the first package installation
- Windows, macOS or Linux

## Run on Windows (quickest)
1. Extract the ZIP file.
2. Open the `PhishShield` folder.
3. Double-click `start_windows.bat`.
4. Wait for package installation and model training to finish.
5. Open **http://127.0.0.1:5000** in your browser.

If Windows blocks the batch file, open PowerShell in this folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000.

## Run manually on macOS/Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

## Train the model again
The model is trained automatically the first time the app starts. To rebuild it from the included CSV:

```bash
python train_model.py
```

The trained model is saved to `model/phishshield_model.joblib`.

## Project structure
```text
PhishShield/
├── app.py
├── detector.py
├── database.py
├── train_model.py
├── requirements.txt
├── start_windows.bat
├── data/
│   └── training_urls.csv
├── model/
│   └── (trained model is generated here)
├── instance/
│   └── (SQLite database is generated here)
├── templates/
│   └── index.html
└── static/
    ├── app.js
    └── style.css
```

## How it works
1. The user enters a URL.
2. The application validates and normalizes the URL. It does not visit the website.
3. Feature extraction calculates URL properties such as length, HTTPS usage, IP-address use, subdomain count, suspicious keywords, punycode, and domain structure.
4. A Random Forest model estimates a phishing probability.
5. Explainable rules calculate additional risk indicators.
6. The two scores are combined: **40% model score + 60% rule score**.
7. The result, reasons and timestamp are saved to SQLite.

## Important academic and security limitations
- The included `training_urls.csv` is a small, hand-labelled **demonstration dataset** so the project runs immediately. It is not a representative production dataset.
- Do not claim that the sample dataset proves high real-world accuracy. For a formal evaluation, replace it with a larger, properly labelled public phishing/legitimate URL dataset, remove duplicates, split it into training and test sets, and report precision, recall, F1-score and a confusion matrix.
- A low-risk result does **not** prove that a site is safe. New phishing URLs may not match known patterns.
- The tool analyses URL text only. It does not inspect page content, certificates, redirects or email messages.
- This is an educational prototype, not a replacement for browser security or professional threat intelligence.

## Main technologies
- Python
- Flask
- scikit-learn (Random Forest)
- SQLite
- HTML, CSS and JavaScript

## API endpoints
- `GET /` - dashboard
- `POST /api/scan` - scan a URL; JSON body: `{"url": "https://example.com"}`
- `GET /api/history` - recent scans and statistics
- `POST /api/history/clear` - clear scan history
