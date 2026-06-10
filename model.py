import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from features import get_feature_vector

# ─── TRAINING DATA ───────────────────────────────────────────────────────────
# Format: (url, label)  0=Legitimate  1=Suspicious  2=Phishing

TRAINING_DATA = [
    # LEGITIMATE (0)
    ("https://www.google.com", 0),
    ("https://www.youtube.com/watch?v=abc123", 0),
    ("https://github.com/user/repo", 0),
    ("https://stackoverflow.com/questions/123", 0),
    ("https://www.amazon.com/products", 0),
    ("https://linkedin.com/in/username", 0),
    ("https://www.microsoft.com/en-us/windows", 0),
    ("https://docs.python.org/3/tutorial", 0),
    ("https://en.wikipedia.org/wiki/Python", 0),
    ("https://www.reddit.com/r/cybersecurity", 0),
    ("https://twitter.com/user", 0),
    ("https://www.instagram.com/user", 0),
    ("https://mail.google.com/mail/u/0/", 0),
    ("https://drive.google.com/drive/folders/abc", 0),
    ("https://www.apple.com/iphone", 0),
    ("https://medium.com/article-title", 0),
    ("https://www.netflix.com/browse", 0),
    ("https://www.coursera.org/learn/python", 0),
    ("https://tryhackme.com/path", 0),
    ("https://www.udemy.com/course/python", 0),

    # SUSPICIOUS (1)
    ("http://paypal-update.com/login", 1),
    ("http://secure-banking-login.net/verify", 1),
    ("http://accounts.google.com.phishing.net/login", 1),
    ("https://free-prize-winner.xyz/claim", 1),
    ("http://amazon-verify-account.tk/signin", 1),
    ("http://support.microsoft.com.help-desk.tk", 1),
    ("http://ebay-secure.com/login?redirect=account", 1),
    ("https://update-your-account.ml/confirm", 1),
    ("http://apple-id-locked.cf/verify", 1),
    ("http://click-here-urgent.top/account-suspend", 1),
    ("http://limited-offer-today.work/claim-prize", 1),
    ("http://www.paypal.com.secure-login.net", 1),

    # PHISHING (2)
    ("http://192.168.1.1/login.php?redirect=paypal", 2),
    ("http://192.0.2.1/secure/banking/signin", 2),
    ("http://10.0.0.1/account/verify/password", 2),
    ("http://paypal.com@evil.com/login", 2),
    ("http://secure-login-verify-credential-update-account.tk/phish", 2),
    ("http://www.secure.signin.verify.update.credential.login.free.xyz/account", 2),
    ("http://goog1e.com/accounts/login/verify", 2),
    ("http://arnazon.com/signin/verify", 2),
    ("http://paypa1.com/cgi-bin/webscr?cmd=login", 2),
    ("http://microsooft.com/account/login/secure", 2),
    ("http://faceb00k.com/login/checkpoint/winner", 2),
    ("http://secure.lloydsbank.com.malicious.tk/online/loginpage", 2),
    ("http://update-required.login.verify.secure.credential.account.xyz", 2),
    ("http://172.16.0.1/banking/signin?session=verify&password=update", 2),
    ("http://appleid.apple.com.id-locked.verify.tk/login@phish.ru", 2),
    ("http://amazonsupport-account.login.verify.secure.ml", 2),
    ("http://dhl-delivery-verify-your-address.cf/track", 2),
    ("http://fedex-shipment-alert.tk/verify-address-login", 2),
    ("http://irs-refund-claim.ga/submit-credentials-free", 2),
    ("http://covid-relief-free-prize-winner.xyz/claim-now-urgent", 2),
]

def train_model():
    print("[*] Preparing training data...")
    X = []
    y = []

    for url, label in TRAINING_DATA:
        try:
            features = get_feature_vector(url)
            X.append(features)
            y.append(label)
        except Exception as e:
            print(f"    Skipping {url}: {e}")

    X = np.array(X)
    y = np.array(y)

    print(f"[*] Training on {len(X)} samples...")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        max_depth=10,
        min_samples_split=2
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[*] Model accuracy: {acc*100:.1f}%")
    print("\n[*] Classification Report:")
    print(classification_report(y_test, y_pred,
          target_names=['Legitimate', 'Suspicious', 'Phishing'],
          zero_division=0))

    with open('model.pkl', 'wb') as f:
        pickle.dump(model, f)

    print("[✓] Model saved to model.pkl")
    return model

if __name__ == '__main__':
    train_model()
