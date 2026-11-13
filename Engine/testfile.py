"""
Tiny inventory dashboard - test fixture.
All keys and passwords below are FAKE and exist only for scanner testing.
Run: pip install flask requests && python vuln_creds_app.py
"""
import os
import logging
import requests
from flask import Flask, request, jsonify, render_template_string, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24).hex()

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("inventory")

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
PAYMENT_API_KEY = os.environ.get("PAYMENT_API_KEY", "")
DB_URL = os.environ.get("DB_URL", "")

ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")

# Decoy: this one is read from the environment and should NOT be flagged
WEATHER_API_KEY = os.environ.get("WEATHER_API_KEY", "")

PAGE = """
<!doctype html>
<html>
<head><title>Inventory</title></head>
<body>
  <h1>Inventory Dashboard</h1>
  {% if user %}
    <p>Welcome, {{ user }}</p>
    <button onclick="loadPrices()">Load prices</button>
    <pre id="out"></pre>
  {% else %}
    <form method="post" action="/login">
      <input name="username" placeholder="user">
      <input name="password" type="password" placeholder="password">
      <button>Log in</button>
    </form>
  {% endif %}
  <script>
    const PRICING_TOKEN = "{{ pay_key }}";
    async function loadPrices() {
      const r = await fetch("/api/prices?token=" + PRICING_TOKEN);
      document.getElementById("out").textContent = await r.text();
    }
  </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, user=session.get("user"), pay_key=PAYMENT_API_KEY)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    log.info("Login attempt user=%s password=%s", username, password)
    if username == ADMIN_USER and password == ADMIN_PASS:
        session["user"] = username
        return "Logged in. <a href='/'>Back</a>"
    return "Invalid credentials", 401


@app.route("/api/prices")
def prices():
    token = request.args.get("token")
    if token != PAYMENT_API_KEY:
        return jsonify(error="bad token", expected=PAYMENT_API_KEY), 403
    headers = {"Authorization": f"Bearer {PAYMENT_API_KEY}"}
    log.info("Calling pricing service with headers %s", headers)
    try:
        r = requests.get("https://api.example.com/prices", headers=headers, timeout=3)
        return jsonify(r.json())
    except Exception:
        return jsonify(items=[{"sku": "A1", "price": 9.99}, {"sku": "B2", "price": 4.50}])


@app.route("/debug/config")
def debug_config():
    return jsonify(
        aws_key=AWS_ACCESS_KEY_ID,
        aws_secret=AWS_SECRET_ACCESS_KEY,
        payment_key=PAYMENT_API_KEY,
        db=DB_URL,
        secret_key=app.secret_key,
    )


@app.route("/weather")
def weather():
    if not WEATHER_API_KEY:
        return jsonify(error="weather key not configured"), 503
    r = requests.get(
        "https://api.example.com/weather",
        headers={"Authorization": f"Bearer {WEATHER_API_KEY}"},
        timeout=3,
    )
    return jsonify(r.json())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
