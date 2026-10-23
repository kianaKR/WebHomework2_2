import os
from datetime import datetime, timedelta, timezone

import jwt
import requests
from flask import Flask, Response, jsonify, request

UPSTREAM = os.environ.get("UPSTREAM_URL", "http://httpbin:8081").rstrip("/")
SECRET = os.environ["JWT_SECRET"]
ALGORITHM = "HS256"
TOKEN_MINUTES = int(os.environ.get("TOKEN_MINUTES", "30"))

# kept simple on purpose: one test user from env
USERS = {
    os.environ.get("DEMO_USER", "student"): os.environ.get("DEMO_PASSWORD", "changeme"),
}

# these headers belong to a single connection and must not be forwarded
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
}

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

app = Flask(__name__)


def unauthorized(message):
    resp = jsonify(error=message)
    resp.status_code = 401
    resp.headers["WWW-Authenticate"] = f'Bearer realm="legacy", error="invalid_token", error_description="{message}"'
    return resp


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if username not in USERS or USERS[username] != password:
        return jsonify(error="wrong username or password"), 401

    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_MINUTES),
    }
    token = jwt.encode(payload, SECRET, algorithm=ALGORITHM)
    return jsonify(access_token=token, token_type="Bearer", expires_in=TOKEN_MINUTES * 60)


def check_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, "missing bearer token"

    token = auth[len("Bearer "):].strip()
    try:
        # algorithms is fixed so a token with alg=none or another alg is rejected
        claims = jwt.decode(token, SECRET, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]})
    except jwt.ExpiredSignatureError:
        return None, "token expired"
    except jwt.InvalidTokenError:
        return None, "invalid token"
    return claims, None


@app.route("/", defaults={"path": ""}, methods=METHODS)
@app.route("/<path:path>", methods=METHODS)
def proxy(path):
    claims, error = check_token()
    if error:
        return unauthorized(error)

    headers = {}
    for name, value in request.headers.items():
        lower = name.lower()
        # token is checked here, the legacy service doesn't need it
        if lower in HOP_BY_HOP or lower in ("host", "authorization", "x-user"):
            continue
        headers[name] = value

    client_ip = request.remote_addr or ""
    previous = request.headers.get("X-Forwarded-For")
    headers["X-Forwarded-For"] = f"{previous}, {client_ip}" if previous else client_ip
    headers["X-Forwarded-Host"] = request.host
    headers["X-Forwarded-Proto"] = request.scheme
    headers["X-User"] = claims["sub"]
    # otherwise requests adds gzip by itself and the client may get gzip it didn't ask for
    headers.setdefault("Accept-Encoding", "identity")

    url = f"{UPSTREAM}/{path}"
    if request.query_string:
        url += "?" + request.query_string.decode()

    try:
        upstream = requests.request(
            request.method,
            url,
            headers=headers,
            data=request.get_data(),
            allow_redirects=False,
            stream=True,
            timeout=30,
        )
    except requests.RequestException:
        return jsonify(error="legacy service is not reachable"), 502

    resp_headers = [
        (name, value) for name, value in upstream.raw.headers.items()
        if name.lower() not in HOP_BY_HOP
    ]

    # decode_content=False so gzip responses are passed as they are
    body = upstream.raw.stream(8192, decode_content=False)
    return Response(body, status=upstream.status_code, headers=resp_headers, direct_passthrough=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "80")))
