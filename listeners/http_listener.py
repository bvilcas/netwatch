"""
NetWatch HTTP Listener
Flask-based web listener that captures and logs all incoming HTTP requests.
Useful for detecting web-based recon, credential stuffing, exploit attempts,
and scanning from tools like Nmap, Nikto, and Metasploit.
"""

import json
from flask import Flask, request
from db.database import get_db
from utils.helpers import setup_logger, print_banner

logger = setup_logger("http_listener")

app = Flask(__name__)


@app.before_request
def log_request():
    """Intercept and log every incoming HTTP request."""
    source_ip = request.remote_addr
    source_port = request.environ.get("REMOTE_PORT", 0)
    method = request.method
    path = request.full_path if request.query_string else request.path
    headers = dict(request.headers)
    body = request.get_data(as_text=True)
    user_agent = request.headers.get("User-Agent", "")
    content_length = request.content_length or 0

    logger.info(f"{method} {path} from {source_ip}:{source_port} : UA: {user_agent[:80]}")

    # Log to database
    try:
        get_db().log_http(
            source_ip=source_ip,
            source_port=source_port,
            method=method,
            path=path,
            headers=headers,
            body=body if body else None,
            user_agent=user_agent,
            content_length=content_length
        )
    except Exception as e:
        logger.error(f"Failed to log request: {e}")


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def catch_all(path):
    """
    Catch-all route : responds to any path and method.
    Returns a generic response to keep scanners engaged.
    """
    return json.dumps({
        "status": "ok",
        "message": "Service running"
    }), 200, {"Content-Type": "application/json"}


def start(host="0.0.0.0", port=8080):
    """Start the HTTP listener."""
    get_db().connect()
    print_banner("HTTP Listener", host, port)
    logger.info("Catching all HTTP methods on all paths")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    start()
