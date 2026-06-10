# PhishGuard AI — Phishing URL Detection System
**Built by Nitin Manral | MCA Cybersecurity Project | 2026**

## What It Does
AI-powered web application that analyzes URLs and classifies them as:
- ✅ **Legitimate** — Safe to visit
- ⚠️ **Suspicious** — Proceed with caution
- 🚨 **Phishing** — Do NOT visit

## Tech Stack
- **Backend:** Python, Flask
- **ML Model:** Scikit-learn (Random Forest Classifier)
- **Feature Extraction:** 8-feature URL analysis pipeline
- **Database:** SQLite (scan history)
- **Frontend:** HTML, CSS, Bootstrap 5, JavaScript

## 8 Features Analyzed
1. URL Length
2. IP Address in URL
3. Dot Count in Domain
4. Phishing Keywords
5. HTTPS Presence
6. @ Symbol Usage
7. Suspicious TLD (.tk, .ml, .xyz, etc.)
8. Subdomain Depth

## Setup & Run (Windows)

### Step 1 — Install dependencies
```
pip install -r requirements.txt
```

### Step 2 — Train the ML model
```
python model.py
```

### Step 3 — Run the app
```
python app.py
```

### Step 4 — Open in browser
```
http://127.0.0.1:5000
```

## Project Structure
```
phishing-detector/
├── app.py              ← Flask main application
├── model.py            ← ML model training script
├── features.py         ← URL feature extraction (8 features)
├── templates/
│   └── index.html      ← Frontend UI
├── requirements.txt    ← Python dependencies
├── model.pkl           ← Trained ML model (auto-generated)
└── database.db         ← SQLite scan history (auto-generated)
```

## Resume Bullet Points
> Built a Flask-based phishing URL detection system using Scikit-learn Random Forest classifier with an 8-feature extraction pipeline — URL pattern analysis, keyword detection, domain heuristics — classifying URLs as Legitimate, Suspicious, or Phishing with SQLite-backed scan history and real-time risk scoring dashboard.
