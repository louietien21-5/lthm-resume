import json
import os
import secrets
import shutil
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request as UrlRequest, urlopen

from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    options_to_json_dict,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from content import PROJECTS_DATA, SITE_DATA
from passkey_store import (
    PasskeyStore,
    PasskeyStoreError,
    StoredCredential,
    base64url_to_bytes,
    bytes_to_base64url,
)
from stats_service import (
    build_dashboard_data,
    build_raw_events_data,
    get_import_options,
    import_plaintext_source,
)

PASSKEY_SETUP_TTL_SECONDS = 900
PASSKEY_CEREMONY_TTL_SECONDS = 300


def _load_local_env(project_root: Path) -> None:
    env_path = project_root / ".env.local"
    if not env_path.exists():
        return

    try:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                # In local development, values from .env.local should win over
                # any stale shell exports so config changes take effect immediately.
                os.environ[key] = value
    except OSError:
        return


def _get_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default

    try:
        return int(raw_value)
    except ValueError:
        try:
            float_value = float(raw_value)
        except ValueError:
            return default
        if float_value.is_integer():
            return int(float_value)
        return default


def _get_bool_env(name: str, default: bool) -> bool:
    raw_value = os.getenv(name, "").strip().lower()
    if not raw_value:
        return default
    if raw_value in {"1", "true", "yes", "on"}:
        return True
    if raw_value in {"0", "false", "no", "off"}:
        return False
    return default


def _parse_csv_env(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


def _build_split_prompt(is_pdf: bool) -> str:
    if is_pdf:
        return """You are reading a Danish Betalingsservice document. Extract ONLY shared household expenses.
INCLUDE: husleje, basisleje, leje, el, strom, gas, internet, vand, varme, A/C varme, tv/antenne, licens, indboforsikring, ejendomsforsikring, streaming, abonnementer, postkasser, faellesudgifter. For bundled rent entries (e.g. Frederiksberg Alle) that show basisleje + varme + postkasser etc., use the single IALT/total shown for that creditor entry.
EXCLUDE: AL Finans, Clever A/S, PROSA, Louis Nielsen, PRIVATSIKRING, motor/bilforsikring, rejseforsikring, ulykkesforsikring, kontaktlinser, lanefinansiering, ydelse, kontogebyr, depositum, forudbetalt leje, MASTERCARD, opkraevningsgebyr.
Return ONLY JSON: [{"name":"...","amount":0}] with dot decimals. If nothing qualifies return []."""
    return """You are reading a Danish Betalingsservice document. Extract ONLY shared household expenses.
INCLUDE: husleje, basisleje, leje, el, strom, gas, internet, vand, varme, A/C varme, tv/antenne, licens, indboforsikring, ejendomsforsikring, streaming, abonnementer, postkasser, faellesudgifter. For bundled rent entries (e.g. Frederiksberg Alle) use the IALT/total for that creditor.
EXCLUDE: AL Finans, Clever A/S, PROSA, Louis Nielsen, PRIVATSIKRING, motor/bilforsikring, rejseforsikring, ulykkesforsikring, kontaktlinser, lanefinansiering, ydelse, kontogebyr, depositum, forudbetalt leje, MASTERCARD.
Return ONLY JSON: [{"name":"...","amount":0}] with dot decimals."""


def _extract_split_text_output(payload: dict[str, Any]) -> str:
    output_text = payload.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text

    for item in payload.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                return content["text"]
    return "[]"


def _coerce_split_amount(value: Any) -> Optional[float]:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None

    candidate = value.strip().replace(" ", "")
    if not candidate:
        return None

    has_comma = "," in candidate
    has_dot = "." in candidate
    if has_comma and has_dot:
        if candidate.rfind(",") > candidate.rfind("."):
            candidate = candidate.replace(".", "").replace(",", ".")
        else:
            candidate = candidate.replace(",", "")
    elif has_comma:
        candidate = candidate.replace(".", "").replace(",", ".")
    else:
        candidate = candidate.replace(",", "")

    try:
        return float(candidate)
    except ValueError:
        return None


def _resolve_stats_dir(project_root: Path) -> Path:
    configured = os.getenv("STATS_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()

    if os.getenv("WEBSITE_SITE_NAME", "").strip():
        return Path("/home/site/data/stats")

    return project_root / "stats"


def _resolve_passkey_store_path(stats_dir: Path) -> Path:
    configured = os.getenv("PASSKEY_STORE_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()
    return stats_dir / ".passkeys.json"


def _seed_stats_dir(stats_dir: Path, bundled_stats_dir: Path) -> None:
    if not bundled_stats_dir.exists() or not bundled_stats_dir.is_dir():
        return

    try:
        same_dir = stats_dir.resolve() == bundled_stats_dir.resolve()
    except OSError:
        same_dir = stats_dir == bundled_stats_dir
    if same_dir:
        return

    try:
        stats_dir.mkdir(parents=True, exist_ok=True)
        if any(stats_dir.iterdir()):
            return
    except OSError:
        return

    for item in bundled_stats_dir.iterdir():
        if not item.is_file():
            continue
        target = stats_dir / item.name
        try:
            shutil.copy2(item, target)
        except OSError:
            continue


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class _SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_limited(self, bucket: str, key: str, limit: int, window_seconds: int) -> bool:
        now = time.time()
        threshold = now - window_seconds
        composite_key = f"{bucket}:{key}"

        with self._lock:
            active = [timestamp for timestamp in self._events.get(composite_key, []) if timestamp >= threshold]
            limited = len(active) >= limit
            if not limited:
                active.append(now)
            self._events[composite_key] = active
        return limited


def create_app() -> Flask:
    app = Flask(__name__)
    project_root = Path(__file__).resolve().parent
    split_dist_dir = project_root / "split_dist"
    rate_limiter = _SlidingWindowRateLimiter()
    _load_local_env(project_root)

    app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", os.getenv("SECRET_KEY", os.urandom(32)))
    app.config["SESSION_COOKIE_NAME"] = os.getenv("SESSION_COOKIE_NAME", "lthm_private_session")
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    app.config["SESSION_COOKIE_SECURE"] = _get_bool_env(
        "SESSION_COOKIE_SECURE",
        bool(os.getenv("WEBSITE_SITE_NAME", "").strip()),
    )
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
        minutes=_get_int_env("PRIVATE_SESSION_LIFETIME_MINUTES", 720)
    )
    app.config["PREFERRED_URL_SCHEME"] = "https"

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    bundled_stats_dir = project_root / "stats"
    stats_dir = _resolve_stats_dir(project_root)
    _seed_stats_dir(stats_dir=stats_dir, bundled_stats_dir=bundled_stats_dir)
    import_options = get_import_options()
    passkey_store = PasskeyStore(_resolve_passkey_store_path(stats_dir))

    def _passkey_rp_name() -> str:
        return os.getenv("PASSKEY_RP_NAME", "Louie Private Tools").strip() or "Louie Private Tools"

    def _passkey_rp_id() -> str:
        configured = os.getenv("PASSKEY_RP_ID", "").strip()
        if configured:
            return configured
        if not os.getenv("WEBSITE_SITE_NAME", "").strip():
            return "localhost"
        return ""

    def _passkey_allowed_origins() -> list[str]:
        configured = _parse_csv_env("PASSKEY_ALLOWED_ORIGINS")
        if configured:
            return configured
        if not os.getenv("WEBSITE_SITE_NAME", "").strip():
            host = os.getenv("HOST", "localhost").strip() or "localhost"
            port = _get_int_env("PORT", 8000)
            return [f"http://{host}:{port}"]
        return []

    def _passkey_user_name() -> str:
        return os.getenv("PASSKEY_USER_NAME", "louie").strip() or "louie"

    def _passkey_user_display_name() -> str:
        return os.getenv("PASSKEY_USER_DISPLAY_NAME", "Louie").strip() or "Louie"

    def _passkey_setup_secret() -> str:
        return os.getenv("PASSKEY_SETUP_SECRET", "").strip()

    def _passkey_runtime_ready() -> bool:
        return bool(_passkey_rp_id() and _passkey_allowed_origins())

    def _login_url(next_path: str = "") -> str:
        params: dict[str, str] = {}
        if next_path:
            params["next"] = next_path
        return url_for("login_page", **params)

    def _safe_next_path(candidate: str) -> str:
        if not candidate:
            return url_for("private_nav")

        parsed = urlparse(candidate)
        if parsed.scheme or parsed.netloc:
            return url_for("private_nav")
        allowed_prefixes = ("/stats", "/split", "/nav", "/passkeys")
        if candidate == "/login":
            return url_for("private_nav")
        if not candidate.startswith(allowed_prefixes):
            return url_for("private_nav")
        return candidate

    def _get_client_ip() -> str:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or "unknown"

    def _session_client_id() -> str:
        client_id = session.get("_client_id")
        if isinstance(client_id, str) and client_id:
            return client_id
        client_id = secrets.token_urlsafe(16)
        session["_client_id"] = client_id
        return client_id

    def _csrf_token() -> str:
        token = session.get("_csrf_token")
        if isinstance(token, str) and token:
            return token
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
        return token

    def _check_rate_limit(bucket: str, limit: int, window_seconds: int, key: Optional[str] = None) -> bool:
        identifier = key or _session_client_id()
        return (
            rate_limiter.is_limited(bucket, f"ip:{_get_client_ip()}", limit, window_seconds)
            or rate_limiter.is_limited(bucket, f"client:{identifier}", limit, window_seconds)
        )

    def _same_origin_request() -> bool:
        target = urlparse(request.host_url)
        for header_name in ("Origin", "Referer"):
            candidate = request.headers.get(header_name, "").strip()
            if not candidate:
                continue
            parsed = urlparse(candidate)
            if parsed.scheme == target.scheme and parsed.netloc == target.netloc:
                return True
        return False

    def _require_csrf(allow_same_origin_fallback: bool = False) -> None:
        submitted = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        expected = _csrf_token()
        if submitted and secrets.compare_digest(submitted, expected):
            return
        if allow_same_origin_fallback and _same_origin_request():
            return
        abort(400, description="Invalid CSRF token.")

    def _handle_passkey_store_error(exc: PasskeyStoreError) -> None:
        app.logger.error("Passkey store failure: %s", exc)
        abort(500, description="Passkey store is invalid.")

    def _passkey_credentials() -> list[StoredCredential]:
        try:
            return passkey_store.credentials()
        except PasskeyStoreError as exc:
            _handle_passkey_store_error(exc)
        return []

    def _passkey_count() -> int:
        try:
            return passkey_store.credential_count()
        except PasskeyStoreError as exc:
            _handle_passkey_store_error(exc)
        return 0

    def _passkey_has_credentials() -> bool:
        return _passkey_count() > 0

    def _passkey_user_handle_b64url() -> str:
        try:
            return passkey_store.user_handle_b64url()
        except PasskeyStoreError as exc:
            _handle_passkey_store_error(exc)
        return ""

    def _passkey_get_credential(credential_id: str) -> Optional[StoredCredential]:
        try:
            return passkey_store.get_credential(credential_id)
        except PasskeyStoreError as exc:
            _handle_passkey_store_error(exc)
        return None

    def _is_private_authenticated() -> bool:
        return bool(session.get("private_authenticated") or session.get("stats_authenticated"))

    def _clear_pending_passkey_state() -> None:
        session.pop("passkey_registration_state", None)
        session.pop("passkey_authentication_state", None)
        session.pop("passkey_bootstrap_user_handle_b64url", None)

    def _pop_pending_state(key: str) -> Optional[dict[str, Any]]:
        payload = session.pop(key, None)
        if not isinstance(payload, dict):
            return None
        issued_at = payload.get("issued_at")
        if not isinstance(issued_at, (int, float)):
            return None
        if (time.time() - float(issued_at)) > PASSKEY_CEREMONY_TTL_SECONDS:
            return None
        return payload

    def _is_setup_unlocked() -> bool:
        raw_value = session.get("passkey_setup_unlocked_at")
        if not isinstance(raw_value, (int, float)):
            return False
        if (time.time() - float(raw_value)) > PASSKEY_SETUP_TTL_SECONDS:
            session.pop("passkey_setup_unlocked_at", None)
            return False
        return True

    def _unlock_setup() -> None:
        session["passkey_setup_unlocked_at"] = time.time()

    def _clear_setup_unlock() -> None:
        session.pop("passkey_setup_unlocked_at", None)

    def _default_passkey_label(existing_count: int) -> str:
        if existing_count == 0:
            return "Primary passkey"
        return f"Passkey {datetime.now().strftime('%Y-%m-%d %H:%M')}"

    def _login_state(next_path: str) -> dict[str, Any]:
        count = _passkey_count()
        setup_unlocked = _is_setup_unlocked()
        setup_secret_configured = bool(_passkey_setup_secret())
        runtime_ready = _passkey_runtime_ready()

        if count > 0 and runtime_ready:
            state = "authenticate"
        elif count == 0 and setup_unlocked and runtime_ready:
            state = "bootstrap"
        elif count == 0 and setup_secret_configured:
            state = "setup-secret"
        else:
            state = "unavailable"

        return {
            "next_path": next_path,
            "passkey_state": state,
            "passkey_count": count,
            "setup_secret_configured": setup_secret_configured,
            "setup_unlocked": setup_unlocked,
            "passkey_runtime_ready": runtime_ready,
            "passkey_store_path": str(passkey_store.path),
            "passkey_client_config": {
                "nextPath": next_path,
                "csrfToken": _csrf_token(),
                "setupUrl": url_for("passkey_setup_secret_submit"),
                "registerOptionsUrl": url_for("passkey_register_options"),
                "registerVerifyUrl": url_for("passkey_register_verify"),
                "authenticateOptionsUrl": url_for("passkey_authenticate_options"),
                "authenticateVerifyUrl": url_for("passkey_authenticate_verify"),
                "passkeysUrl": url_for("passkey_management"),
            },
        }

    def _management_context(feedback: Optional[dict[str, str]] = None) -> dict[str, Any]:
        credentials = _passkey_credentials()
        if feedback is None:
            feedback = session.pop("passkey_feedback", None)
        return {
            "passkey_feedback": feedback,
            "credentials": [
                {
                    "credential_id": credential.credential_id,
                    "label": credential.label,
                    "created_at": credential.created_at,
                    "last_used_at": credential.last_used_at,
                    "device_type": credential.device_type.replace("_", " "),
                    "backed_up": credential.backed_up,
                    "transports": ", ".join(credential.transports) if credential.transports else "unknown",
                }
                for credential in credentials
            ],
            "can_remove": len(credentials) > 1,
            "passkey_client_config": {
                "nextPath": url_for("passkey_management"),
                "csrfToken": _csrf_token(),
                "registerOptionsUrl": url_for("passkey_register_options"),
                "registerVerifyUrl": url_for("passkey_register_verify"),
                "passkeysUrl": url_for("passkey_management"),
            },
        }

    @app.context_processor
    def inject_private_session_state():
        return {
            "private_session_authenticated": _is_private_authenticated(),
            "csrf_token": _csrf_token(),
        }

    def _private_auth_redirect():
        if _is_private_authenticated():
            return None
        next_target = request.full_path if request.query_string else request.path
        return redirect(_login_url(next_target))

    def _import_context(
        feedback: Optional[Dict[str, str]] = None,
        selected_source: Optional[str] = None,
    ) -> Dict[str, object]:
        if feedback is None:
            feedback = session.pop("stats_import_feedback", None)
        if selected_source is None:
            selected_source = session.pop("stats_import_selected_source", "")
        if not selected_source and import_options:
            selected_source = import_options[0]["key"]
        return {
            "import_options": import_options,
            "import_feedback": feedback,
            "import_selected_source": selected_source,
        }

    @app.get("/")
    def home():
        return render_template("index.html", site=SITE_DATA)

    @app.get("/projects")
    def projects():
        return render_template("projects.html", data=PROJECTS_DATA)

    @app.get("/favicon.ico")
    def favicon_ico():
        return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/x-icon")

    @app.get("/apple-touch-icon.png")
    def apple_touch_icon():
        return send_from_directory(app.static_folder, "apple-touch-icon.png", mimetype="image/png")

    @app.get("/login")
    def login_page():
        if _is_private_authenticated():
            next_path = _safe_next_path(request.args.get("next", ""))
            return redirect(next_path if next_path != url_for("private_nav") else url_for("private_nav"))

        error = session.pop("login_error", None)
        next_path = _safe_next_path(request.args.get("next", ""))
        return render_template("login.html", error=error, **_login_state(next_path))

    @app.post("/auth/passkeys/setup-secret")
    def passkey_setup_secret_submit():
        _require_csrf()
        if _check_rate_limit("setup_secret", limit=5, window_seconds=900):
            return jsonify({"error": "Setup failed."}), 429

        payload = request.get_json(silent=True) or {}
        secret = str(payload.get("secret", "")).strip()
        if _passkey_has_credentials():
            return jsonify({"error": "Setup failed."}), 400
        configured_secret = _passkey_setup_secret()
        if not configured_secret:
            return jsonify({"error": "Setup failed."}), 503
        if not secrets.compare_digest(secret, configured_secret):
            return jsonify({"error": "Setup failed."}), 401

        _unlock_setup()
        return jsonify({"ok": True})

    @app.post("/auth/passkeys/register/options")
    def passkey_register_options():
        _require_csrf()
        if _check_rate_limit("passkey_register", limit=10, window_seconds=600):
            return jsonify({"error": "Passkey request failed."}), 429
        if not _passkey_runtime_ready():
            return jsonify({"error": "Passkeys are not configured right now."}), 503

        payload = request.get_json(silent=True) or {}
        next_path = _safe_next_path(str(payload.get("nextPath", "")))
        requested_label = str(payload.get("label", "")).strip()

        credentials = _passkey_credentials()
        bootstrap_allowed = not credentials and _is_setup_unlocked()
        management_allowed = _is_private_authenticated()
        if not bootstrap_allowed and not management_allowed:
            return jsonify({"error": "Passkey request failed."}), 403

        user_handle_b64url = _passkey_user_handle_b64url()
        if not user_handle_b64url:
            user_handle_b64url = session.get("passkey_bootstrap_user_handle_b64url", "")
            if not isinstance(user_handle_b64url, str) or not user_handle_b64url:
                user_handle_b64url = bytes_to_base64url(secrets.token_bytes(32))
                session["passkey_bootstrap_user_handle_b64url"] = user_handle_b64url

        challenge = secrets.token_bytes(32)
        options = generate_registration_options(
            rp_id=_passkey_rp_id(),
            rp_name=_passkey_rp_name(),
            user_name=_passkey_user_name(),
            user_display_name=_passkey_user_display_name(),
            user_id=base64url_to_bytes(user_handle_b64url),
            challenge=challenge,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                require_resident_key=True,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[credential.descriptor() for credential in credentials],
        )

        session["passkey_registration_state"] = {
            "challenge": bytes_to_base64url(challenge),
            "issued_at": time.time(),
            "label": requested_label or _default_passkey_label(len(credentials)),
            "mode": "management" if management_allowed and credentials else "bootstrap",
            "next_path": next_path,
            "user_handle_b64url": user_handle_b64url,
        }
        return jsonify({"ok": True, "options": options_to_json_dict(options)})

    @app.post("/auth/passkeys/register/verify")
    def passkey_register_verify():
        _require_csrf()
        if _check_rate_limit("passkey_register", limit=10, window_seconds=600):
            return jsonify({"error": "Passkey request failed."}), 429

        state = _pop_pending_state("passkey_registration_state")
        if not state:
            return jsonify({"error": "Passkey request failed."}), 400

        payload = request.get_json(silent=True) or {}
        credential_payload = payload.get("credential")
        if not isinstance(credential_payload, dict):
            return jsonify({"error": "Passkey request failed."}), 400

        try:
            parsed_credential = parse_registration_credential_json(credential_payload)
            verified = verify_registration_response(
                credential=parsed_credential,
                expected_challenge=base64url_to_bytes(state["challenge"]),
                expected_rp_id=_passkey_rp_id(),
                expected_origin=_passkey_allowed_origins(),
                require_user_verification=True,
            )
        except Exception:
            app.logger.exception("Passkey registration verification failed")
            return jsonify({"error": "Passkey request failed."}), 400

        response_payload = credential_payload.get("response", {})
        transports = response_payload.get("transports", [])
        if not isinstance(transports, list):
            transports = []

        credential = StoredCredential(
            credential_id=bytes_to_base64url(verified.credential_id),
            public_key=bytes_to_base64url(verified.credential_public_key),
            sign_count=verified.sign_count,
            transports=[str(item) for item in transports if isinstance(item, str)],
            device_type=verified.credential_device_type.value,
            backed_up=verified.credential_backed_up,
            label=str(state.get("label", _default_passkey_label(0))),
            created_at=_utc_now_iso(),
            last_used_at="",
        )

        try:
            passkey_store.add_credential(str(state["user_handle_b64url"]), credential)
        except PasskeyStoreError as exc:
            _handle_passkey_store_error(exc)

        _clear_setup_unlock()
        session.pop("passkey_bootstrap_user_handle_b64url", None)
        session["private_authenticated"] = True
        session["stats_authenticated"] = True
        session.permanent = True
        return jsonify({"ok": True, "redirectTo": _safe_next_path(str(state.get("next_path", "")))})

    @app.post("/auth/passkeys/authenticate/options")
    def passkey_authenticate_options():
        _require_csrf()
        if _check_rate_limit("passkey_auth", limit=12, window_seconds=600):
            return jsonify({"error": "Sign-in failed."}), 429
        if not _passkey_runtime_ready():
            return jsonify({"error": "Passkeys are not configured right now."}), 503

        credentials = _passkey_credentials()
        if not credentials:
            return jsonify({"error": "Sign-in failed."}), 400

        payload = request.get_json(silent=True) or {}
        next_path = _safe_next_path(str(payload.get("nextPath", "")))
        challenge = secrets.token_bytes(32)
        options = generate_authentication_options(
            rp_id=_passkey_rp_id(),
            challenge=challenge,
            allow_credentials=[credential.descriptor() for credential in credentials],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        session["passkey_authentication_state"] = {
            "challenge": bytes_to_base64url(challenge),
            "issued_at": time.time(),
            "next_path": next_path,
        }
        return jsonify({"ok": True, "options": options_to_json_dict(options)})

    @app.post("/auth/passkeys/authenticate/verify")
    def passkey_authenticate_verify():
        _require_csrf()
        if _check_rate_limit("passkey_auth", limit=12, window_seconds=600):
            return jsonify({"error": "Sign-in failed."}), 429

        state = _pop_pending_state("passkey_authentication_state")
        if not state:
            return jsonify({"error": "Sign-in failed."}), 400

        payload = request.get_json(silent=True) or {}
        credential_payload = payload.get("credential")
        if not isinstance(credential_payload, dict):
            return jsonify({"error": "Sign-in failed."}), 400

        credential_id = credential_payload.get("id")
        if not isinstance(credential_id, str) or not credential_id:
            return jsonify({"error": "Sign-in failed."}), 400

        stored_credential = _passkey_get_credential(credential_id)
        if stored_credential is None:
            return jsonify({"error": "Sign-in failed."}), 400

        try:
            parsed_credential = parse_authentication_credential_json(credential_payload)
            verified = verify_authentication_response(
                credential=parsed_credential,
                expected_challenge=base64url_to_bytes(state["challenge"]),
                expected_rp_id=_passkey_rp_id(),
                expected_origin=_passkey_allowed_origins(),
                credential_public_key=base64url_to_bytes(stored_credential.public_key),
                credential_current_sign_count=stored_credential.sign_count,
                require_user_verification=True,
            )
        except Exception:
            app.logger.exception("Passkey authentication verification failed")
            return jsonify({"error": "Sign-in failed."}), 400

        try:
            passkey_store.update_credential(
                credential_id=stored_credential.credential_id,
                sign_count=verified.new_sign_count,
                device_type=verified.credential_device_type.value,
                backed_up=verified.credential_backed_up,
                last_used_at=_utc_now_iso(),
            )
        except PasskeyStoreError as exc:
            _handle_passkey_store_error(exc)

        session["private_authenticated"] = True
        session["stats_authenticated"] = True
        session.permanent = True
        return jsonify({"ok": True, "redirectTo": _safe_next_path(str(state.get("next_path", "")))})

    @app.get("/passkeys")
    def passkey_management():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect
        return render_template("passkeys.html", **_management_context())

    @app.post("/passkeys/remove")
    def passkey_remove():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect
        _require_csrf()

        credential_id = request.form.get("credential_id", "").strip()
        feedback: dict[str, str]
        try:
            passkey_store.remove_credential(credential_id)
            feedback = {"level": "ok", "text": "Passkey removed."}
        except PasskeyStoreError as exc:
            feedback = {"level": "error", "text": str(exc)}

        session["passkey_feedback"] = feedback
        return redirect(url_for("passkey_management"))

    @app.get("/nav")
    def private_nav():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        return render_template("nav.html")

    @app.get("/split")
    def split_entry():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect
        return redirect(url_for("split_frontend", path=""))

    @app.get("/split/api/health")
    def split_api_health():
        if not _is_private_authenticated():
            abort(401)
        return jsonify({"ok": True, "openaiConfigured": bool(os.getenv("OPENAI_API_KEY", "").strip())})

    @app.post("/split/api/extract-expenses")
    def split_api_extract_expenses():
        if not _is_private_authenticated():
            abort(401)
        _require_csrf(allow_same_origin_fallback=True)
        if _check_rate_limit("split_extract", limit=20, window_seconds=600):
            return jsonify({"error": "Too many requests."}), 429

        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            return jsonify({"error": "OPENAI_API_KEY is not set."}), 500

        payload = request.get_json(silent=True) or {}
        data = payload.get("data")
        mime_type = payload.get("mimeType")
        kind = payload.get("kind")

        if not data or not mime_type or not kind:
            return jsonify({"error": "Missing data, mimeType, or kind."}), 400

        is_pdf = kind == "pdf"
        if is_pdf:
            user_content: list[dict[str, Any]] = [
                {
                    "type": "input_file",
                    "filename": "statement.pdf",
                    "file_data": f"data:{mime_type};base64,{data}",
                },
                {
                    "type": "input_text",
                    "text": "Extract shared household expenses. JSON only.",
                },
            ]
        else:
            user_content = [
                {
                    "type": "input_image",
                    "image_url": f"data:{mime_type};base64,{data}",
                },
                {
                    "type": "input_text",
                    "text": "Extract shared household expenses. JSON only.",
                },
            ]

        openai_payload = {
            "model": "gpt-4.1-mini",
            "input": [
                {
                    "role": "system",
                    "content": [{"type": "input_text", "text": _build_split_prompt(is_pdf)}],
                },
                {
                    "role": "user",
                    "content": user_content,
                },
            ],
        }

        try:
            api_request = UrlRequest(
                "https://api.openai.com/v1/responses",
                data=json.dumps(openai_payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method="POST",
            )
            with urlopen(api_request, timeout=90) as response:
                response_payload = json.load(response)
        except HTTPError as exc:
            app.logger.warning("OpenAI request failed with status %s", exc.code)
            return jsonify({"error": "OpenAI request failed."}), 502
        except URLError as exc:
            app.logger.warning("OpenAI request failed: %s", exc.reason)
            return jsonify({"error": "OpenAI request failed."}), 502
        except Exception:
            app.logger.exception("Unexpected split extraction failure")
            return jsonify({"error": "Unexpected extraction failure."}), 500

        text_block = _extract_split_text_output(response_payload)
        cleaned = text_block.replace("```json", "").replace("```", "").strip()

        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            return jsonify({"error": "OpenAI returned invalid JSON."}), 502

        expense_items: Any = parsed
        if isinstance(parsed, dict):
            expense_items = parsed.get("expenses", [])

        expenses = []
        if isinstance(expense_items, list):
            for item in expense_items:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                amount = _coerce_split_amount(item.get("amount"))
                if isinstance(name, str) and amount is not None:
                    cleaned_name = name.strip()
                    if cleaned_name:
                        expenses.append({"name": cleaned_name, "amount": amount})

        return jsonify({"expenses": expenses})

    @app.get("/split/", defaults={"path": ""})
    @app.get("/split/<path:path>")
    def split_frontend(path: str):
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        if path.startswith("api/") or path == "healthz":
            abort(404)

        if split_dist_dir.exists():
            target = split_dist_dir / path
            if path and target.exists() and target.is_file():
                return send_from_directory(split_dist_dir, path)
            response = send_from_directory(split_dist_dir, "index.html")
            response.set_cookie(
                "split_csrf_token",
                _csrf_token(),
                secure=app.config["SESSION_COOKIE_SECURE"],
                httponly=False,
                samesite=app.config["SESSION_COOKIE_SAMESITE"],
            )
            return response

        abort(404)

    @app.post("/logout")
    def logout():
        _require_csrf()
        session.clear()
        return redirect(_login_url())

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok"), 200

    @app.get("/stats/login")
    def stats_login():
        next_path = _safe_next_path(request.args.get("next", url_for("stats_page")))
        return redirect(_login_url(next_path))

    @app.post("/stats/logout")
    def stats_logout():
        return logout()

    @app.get("/stats")
    def stats_page():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        window = request.args.get("window", "90d")
        dashboard = build_dashboard_data(stats_dir=stats_dir, window=window)
        return render_template("stats.html", dashboard=dashboard)

    @app.get("/stats/dashboard")
    def stats_dashboard():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        window = request.args.get("window", "90d")
        dashboard = build_dashboard_data(stats_dir=stats_dir, window=window)
        return render_template("partials/stats_dashboard.html", dashboard=dashboard)

    @app.get("/stats/raw")
    def stats_raw():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        raw = build_raw_events_data(
            stats_dir=stats_dir,
            window=request.args.get("window", "90d"),
            source=request.args.get("source", "all"),
            day=request.args.get("day", ""),
            limit=request.args.get("limit", "120"),
        )
        return render_template("partials/stats_raw_table.html", raw=raw)

    @app.get("/stats/import")
    def stats_import_page():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect

        return render_template("stats_import.html", **_import_context())

    @app.post("/stats/import")
    def stats_import_plaintext():
        auth_redirect = _private_auth_redirect()
        if auth_redirect:
            return auth_redirect
        _require_csrf()

        source = request.form.get("source", "").strip()
        payload = request.form.get("payload", "")
        selected_source = source if source else None

        try:
            result = import_plaintext_source(stats_dir=stats_dir, source=source, payload=payload)
            feedback = {
                "level": "ok",
                "text": (
                    "Imported {0} lines into {1}. "
                    "{2} unique events written ({3} non-event lines ignored)."
                ).format(
                    int(result["incoming_events"]),
                    str(result["target_file"]),
                    int(result["written_events"]),
                    int(result["ignored_lines"]),
                ),
            }
        except ValueError as exc:
            feedback = {"level": "error", "text": str(exc)}
        except OSError:
            feedback = {
                "level": "error",
                "text": "Could not write import file in {0}. Configure STATS_DIR to a writable path.".format(
                    stats_dir
                ),
            }

        session["stats_import_feedback"] = feedback
        if selected_source:
            session["stats_import_selected_source"] = selected_source
        return redirect(url_for("stats_import_page"))

    return app


app = create_app()


if __name__ == "__main__":
    from waitress import serve

    host = os.getenv("HOST", "localhost")
    port = _get_int_env("PORT", 8000)
    threads = _get_int_env("WAITRESS_THREADS", 8)
    print(f"Open: http://{host}:{port}")
    serve(app, host=host, port=port, threads=threads)
