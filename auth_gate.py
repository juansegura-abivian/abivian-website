"""
auth_gate.py - Authentication gate for the Abivian Platform.

Validates the short-lived JWT issued by the Netlify auth-callback function.
Call require_auth() at the top of main() in case.py before any UI renders.

Usage in case.py:
    import auth_gate

    def main():
        st.set_page_config(...)
        auth_gate.require_auth()   # stops here if not authenticated
        # ... rest of your app
"""

import os
import streamlit as st
import jwt
from datetime import datetime

# ── Configuration ──────────────────────────────────────────────────────────────

JWT_SECRET = os.environ.get("JWT_SECRET", "")
LOGIN_URL = os.environ.get(
    "ABIVIAN_LOGIN_URL",
    "https://abivian.com/.netlify/functions/auth-login"
)

# ── Public API ─────────────────────────────────────────────────────────────────

def require_auth():
    """
    Call at the top of main(). 
    - If already authenticated in session → returns immediately.
    - If token in query params → validates, sets session, clears URL, reruns.
    - Otherwise → shows login screen and stops execution.
    """
    # Already authenticated in this session
    if st.session_state.get("authenticated"):
        return

    # Check for token arriving from Netlify callback
    token = st.query_params.get("token")

    if token:
        _handle_token(token)
    else:
        # Check for error param from Netlify
        error_param = st.query_params.get("error")
        error_msg = _error_message(error_param) if error_param else None
        _show_login_screen(error=error_msg)
        st.stop()


def get_current_user() -> dict:
    """
    Returns the authenticated user dict from session state.
    Keys: user_id, email, first_name, last_name
    Returns empty dict if not authenticated.
    """
    if not st.session_state.get("authenticated"):
        return {}
    return {
        "user_id":    st.session_state.get("user_id", ""),
        "email":      st.session_state.get("user_email", ""),
        "first_name": st.session_state.get("user_first_name", ""),
        "last_name":  st.session_state.get("user_last_name", ""),
    }


# ── Internal helpers ───────────────────────────────────────────────────────────

def _handle_token(token: str):
    """Validate JWT and set session state, or show error."""
    if not JWT_SECRET:
        _show_login_screen(error="Server configuration error. Please contact support.")
        st.stop()

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer="abivian.com",
        )

        # Store user in session
        st.session_state.authenticated    = True
        st.session_state.user_id          = payload.get("user_id", "")
        st.session_state.user_email       = payload.get("email", "")
        st.session_state.user_first_name  = payload.get("first_name", "")
        st.session_state.user_last_name   = payload.get("last_name", "")
        st.session_state.auth_timestamp   = datetime.utcnow().isoformat()

        # Clear token from URL immediately
        st.query_params.clear()
        st.rerun()

    except jwt.ExpiredSignatureError:
        st.query_params.clear()
        _show_login_screen(error="Your login link has expired. Please sign in again.")
        st.stop()

    except jwt.InvalidIssuerError:
        st.query_params.clear()
        _show_login_screen(error="Invalid login source. Please sign in via abivian.com.")
        st.stop()

    except jwt.InvalidTokenError:
        st.query_params.clear()
        _show_login_screen(error="Invalid session token. Please sign in again.")
        st.stop()


def _show_login_screen(error: str = None):
    """Render the login screen with optional error message."""

    st.markdown("""
        <style>
        /* Hide Streamlit chrome */
        #MainMenu, footer, header { visibility: hidden; }

        /* Center the login card */
        .block-container {
            max-width: 440px !important;
            padding-top: 8vh !important;
            margin: 0 auto;
        }

        /* Card */
        .login-card {
            background: #ffffff;
            border: 1px solid #e8e8e8;
            border-radius: 12px;
            padding: 48px 40px 40px 40px;
            text-align: center;
            box-shadow: 0 2px 16px rgba(0,0,0,0.06);
        }

        .login-title {
            font-family: 'Inter', sans-serif;
            font-size: 22px;
            font-weight: 600;
            color: #1a1a1a;
            margin: 16px 0 4px 0;
            letter-spacing: -0.3px;
        }

        .login-subtitle {
            font-family: 'Inter', sans-serif;
            font-size: 13px;
            color: #888;
            margin-bottom: 32px;
            letter-spacing: 0.3px;
            text-transform: uppercase;
        }

        .login-divider {
            border: none;
            border-top: 1px solid #f0f0f0;
            margin: 24px 0;
        }

        .login-footer {
            font-size: 11px;
            color: #bbb;
            margin-top: 24px;
        }
        </style>
    """, unsafe_allow_html=True)

    # Center column
    _, col, _ = st.columns([1, 4, 1])

    with col:
        st.markdown('<div class="login-card">', unsafe_allow_html=True)

        # Logo
        try:
            st.image("logo.png", width=140)
        except Exception:
            st.markdown("**ABIVIAN**")

        st.markdown('<p class="login-title">Abivian Platform</p>', unsafe_allow_html=True)
        st.markdown('<p class="login-subtitle">Deterministic AI for Compliance</p>', unsafe_allow_html=True)
        st.markdown('<hr class="login-divider">', unsafe_allow_html=True)

        # Error message
        if error:
            st.error(error)
            st.markdown("<br>", unsafe_allow_html=True)

        # Login button
        st.link_button(
            "Sign in with Google",
            url=LOGIN_URL,
            use_container_width=True,
            type="primary",
        )

        st.markdown(
            '<p class="login-footer">Access is restricted to authorised users only.</p>',
            unsafe_allow_html=True
        )
        st.markdown('</div>', unsafe_allow_html=True)


def _error_message(error_code: str) -> str:
    messages = {
        "auth_failed":   "Authentication failed. Please try again.",
        "login_failed":  "Could not initiate login. Please try again.",
        "missing_code":  "Login was incomplete. Please try again.",
        "unauthorized":  "Access denied. Your account is not authorised to use this platform.",
    }
    return messages.get(error_code, "An error occurred. Please try again.")
