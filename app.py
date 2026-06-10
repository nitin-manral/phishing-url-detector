from flask import Flask, render_template, request, jsonify
import pickle
import numpy as np
import sqlite3
import os
from datetime import datetime
from features import get_feature_vector, get_feature_explanation

app = Flask(__name__)

MODEL_PATH = 'model.pkl'
DB_PATH = 'database.db'

LABELS = {0: 'Legitimate', 1: 'Suspicious', 2: 'Phishing'}
LABEL_COLORS = {0: 'legitimate', 1: 'suspicious', 2: 'phishing'}
RISK_SCORES = {0: 15, 1: 55, 2: 92}
RISK_MESSAGES = {
    0: "This URL appears to be legitimate. Standard caution still advised.",
    1: "This URL has suspicious characteristics. Do NOT enter credentials.",
    2: "HIGH RISK — Strong phishing indicators detected. Do NOT visit this URL."
}

# ─── DB SETUP ────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            risk_score INTEGER,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def log_scan(url, result, risk_score):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        'INSERT INTO scan_history (url, result, risk_score, timestamp) VALUES (?, ?, ?, ?)',
        (url, result, risk_score, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    conn.commit()
    conn.close()

def get_history(limit=10):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT url, result, risk_score, timestamp FROM scan_history ORDER BY id DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM scan_history')
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scan_history WHERE result='Phishing'")
    phishing = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scan_history WHERE result='Suspicious'")
    suspicious = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scan_history WHERE result='Legitimate'")
    legit = c.fetchone()[0]
    conn.close()
    return {'total': total, 'phishing': phishing, 'suspicious': suspicious, 'legitimate': legit}

# ─── LOAD MODEL ──────────────────────────────────────────────────────────────

def load_model():
    if not os.path.exists(MODEL_PATH):
        print("[!] Model not found. Training now...")
        from model import train_model
        return train_model()
    with open(MODEL_PATH, 'rb') as f:
        return pickle.load(f)

model = None

# ─── ROUTES ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    stats = get_stats()
    history = get_history(8)
    return render_template('index.html', stats=stats, history=history)

@app.route('/scan', methods=['POST'])
def scan():
    global model
    if model is None:
        model = load_model()

    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'Please enter a URL'}), 400

    if len(url) > 2000:
        return jsonify({'error': 'URL too long'}), 400

    try:
        features = get_feature_vector(url)
        features_array = np.array(features).reshape(1, -1)
        prediction = model.predict(features_array)[0]
        proba = model.predict_proba(features_array)[0]

        label = LABELS[prediction]
        color = LABEL_COLORS[prediction]
        risk_score = RISK_SCORES[prediction]
        message = RISK_MESSAGES[prediction]
        explanations = get_feature_explanation(url)
        confidence = round(max(proba) * 100, 1)

        log_scan(url, label, risk_score)

        return jsonify({
            'url': url,
            'label': label,
            'color': color,
            'risk_score': risk_score,
            'message': message,
            'confidence': confidence,
            'explanations': [
                {'feature': e[0], 'status': e[1], 'detail': e[2]}
                for e in explanations
            ],
            'probabilities': {
                'legitimate': round(proba[0] * 100, 1),
                'suspicious': round(proba[1] * 100, 1),
                'phishing': round(proba[2] * 100, 1),
            }
        })

    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/history')
def history():
    rows = get_history(20)
    return jsonify([
        {'url': r[0], 'result': r[1], 'risk_score': r[2], 'timestamp': r[3]}
        for r in rows
    ])

@app.route('/stats')
def stats():
    return jsonify(get_stats())

# ─── MAIN ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    model = load_model()
    print("\n[✓] PhishGuard AI running at http://127.0.0.1:5000")
    print("[✓] Press Ctrl+C to stop\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
