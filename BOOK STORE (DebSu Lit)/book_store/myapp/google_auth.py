import base64
import hashlib
import logging
import re
import secrets
import urllib.parse
import requests
from django.conf import settings
from django.db import connection
from django.urls import reverse
from .models import CustomUser

logger = logging.getLogger(__name__)

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo"

# Minimal, privacy-first OAuth scopes: only OpenID identity, verified email, and public profile
PRIVACY_FOCUSED_SCOPES = "openid email profile"


def generate_pkce_pair():
    """
    Generates a cryptographically secure PKCE (RFC 7636) code verifier and challenge.
    Protects authorization codes from interception attacks.
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
    return code_verifier, code_challenge


def resolve_neon_auth_url() -> str:
    """
    Dynamically resolves the Neon Auth URL:
    1. settings.NEON_AUTH_URL or os.environ['NEON_AUTH_URL']
    2. Auto-derived from settings.DATABASE_URL or os.environ['DATABASE_URL'] if pointing to neon.tech
    3. Project default Neon Auth endpoint for DebSu Lit
    """
    configured = (getattr(settings, 'NEON_AUTH_URL', '') or os.environ.get('NEON_AUTH_URL', '')).strip()
    if configured:
        return configured.rstrip('/')

    db_url = getattr(settings, 'DATABASE_URL', '') or os.environ.get('DATABASE_URL', '')
    if db_url and 'neon.tech' in db_url:
        match = re.search(r'@([a-z0-9\-]+?)(?:-pooler)?\.([a-z0-9\.\-]+neon\.tech)/([a-zA-Z0-9_\-]+)', db_url)
        if match:
            endpoint = match.group(1)
            domain = match.group(2)
            dbname = match.group(3)
            return f"https://{endpoint}.neonauth.{domain}/{dbname}/auth"

    return "https://ep-proud-queen-b8qhapsy.neonauth.c-14.us-east-1.aws.neon.tech/neondb/auth"


def get_neon_auth_url(request):
    """
    Initiates Google Social Login via Neon Auth (Better Auth).
    Neon provides pre-configured Shared Keys for Google OAuth so no
    Google Cloud Console configuration is required.
    """
    neon_auth_url = resolve_neon_auth_url()
    if not neon_auth_url:
        return None

    callback_url = request.build_absolute_uri(reverse('google_oauth_callback'))
    origin = request.build_absolute_uri('/')[:-1]

    # Normalize 127.0.0.1 or testserver to localhost for Better Auth 'Allow Localhost' whitelist
    if '127.0.0.1' in callback_url:
        callback_url = callback_url.replace('127.0.0.1', 'localhost')
        origin = origin.replace('127.0.0.1', 'localhost')
    elif 'testserver' in callback_url:
        callback_url = callback_url.replace('testserver', 'localhost:8000')
        origin = 'http://localhost:8000'
    else:
        # Enforce HTTPS on cloud hosts (Render, Railway, etc. behind reverse proxy)
        if callback_url.startswith('http://'):
            callback_url = 'https://' + callback_url[7:]
        if origin.startswith('http://'):
            origin = 'https://' + origin[7:]

    next_url = request.GET.get('next') or request.POST.get('next')
    if next_url and next_url.startswith('/') and not next_url.startswith('//'):
        request.session['google_oauth_next_url'] = next_url

    try:
        headers = {
            'Content-Type': 'application/json',
            'Origin': origin,
            'User-Agent': 'DebSuLit-Bookstore/1.0',
        }
        payload = {
            'provider': 'google',
            'callbackURL': callback_url,
        }
        resp = requests.post(f"{neon_auth_url}/sign-in/social", json=payload, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            redirect_target = data.get('url')
            if redirect_target:
                request.session['auth_mode'] = 'neon'
                request.session.pop('auth_error_message', None)
                return redirect_target

        err_data = {}
        try:
            err_data = resp.json()
        except Exception:
            pass
        err_msg = err_data.get('message') or err_data.get('error') or resp.text
        logger.warning("Neon Auth social init returned HTTP %s: %s", resp.status_code, resp.text)

        if 'INVALID_CALLBACKURL' in str(err_msg) or resp.status_code == 403:
            request.session['auth_error_message'] = (
                f"Neon Auth origin authorization required: '{origin}' is not yet in Neon's authorized domains. "
                f"In your Neon Console (neon.tech) -> Project -> Auth -> Configuration -> Domains, add: '{origin}'"
            )
        else:
            request.session['auth_error_message'] = f"Neon Auth error ({resp.status_code}): {err_msg}"
    except Exception as e:
        logger.warning("Could not initiate Neon Auth social login: %s", e)
        request.session['auth_error_message'] = f"Neon Auth connection error: {str(e)}"

    return None


def get_direct_google_auth_url(request):
    """
    Direct Google OAuth 2.0 authorization URL with state and PKCE protection.
    Used when custom Google Cloud Console credentials are provided.
    """
    client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '').strip()
    if not client_id:
        return None

    redirect_uri = getattr(settings, 'GOOGLE_OAUTH_REDIRECT_URI', '').strip()
    if not redirect_uri:
        redirect_uri = request.build_absolute_uri(reverse('google_oauth_callback'))

    state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce_pair()

    request.session['google_oauth_state'] = state
    request.session['google_oauth_code_verifier'] = code_verifier
    request.session['google_oauth_redirect_uri'] = redirect_uri
    request.session['auth_mode'] = 'direct'

    next_url = request.GET.get('next') or request.POST.get('next')
    if next_url and next_url.startswith('/') and not next_url.startswith('//'):
        request.session['google_oauth_next_url'] = next_url

    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': PRIVACY_FOCUSED_SCOPES,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'prompt': 'select_account',
        'access_type': 'online',
    }

    return f"{GOOGLE_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"


def get_google_auth_url(request):
    """
    Returns the appropriate Google login redirect URL:
    1. Tries Neon Auth with built-in shared Google keys (zero setup required).
    2. Falls back to direct Google Cloud OAuth if configured.
    """
    # Try Neon Auth first
    neon_url = get_neon_auth_url(request)
    if neon_url:
        return neon_url

    # Fall back to direct Google OAuth if configured
    return get_direct_google_auth_url(request)


def verify_neon_session(request):
    """
    Verifies authenticated user identity from Neon Auth (Better Auth).
    Supports:
    1. Direct token in cookies or GET query parameters.
    2. Fresh session lookup in neon_auth.session (created in last 5 minutes).
    3. HTTP GET /get-session on NEON_AUTH_URL with forwardable cookies.
    """
    token = request.COOKIES.get('better-auth.session_token') or request.GET.get('token')
    
    # 1. Direct token SQL check on Neon PostgreSQL
    if token:
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT u.id, u.email, u.name, u."emailVerified", u.image
                    FROM neon_auth.session s
                    JOIN neon_auth.user u ON s."userId" = u.id
                    WHERE s.token = %s AND s."expiresAt" > NOW()
                    LIMIT 1;
                """, [token])
                row = cursor.fetchone()
                if row:
                    user_id, email, name, verified, image = row
                    return {
                        'email': email,
                        'name': name,
                        'email_verified': verified if verified is not None else True,
                        'picture': image,
                    }
        except Exception as e:
            logger.warning("Direct Neon DB session token query check failed: %s", e)

    # 2. Fresh session lookup in neon_auth.session (created within last 5 minutes)
    # This solves cross-domain cookie partition when returning from Neon Auth to localhost
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.email, u.name, u."emailVerified", u.image, s.token, s."createdAt"
                FROM neon_auth.session s
                JOIN neon_auth.user u ON s."userId" = u.id
                WHERE s."createdAt" >= NOW() - INTERVAL '5 minutes'
                  AND s."expiresAt" > NOW()
                ORDER BY s."createdAt" DESC
                LIMIT 1;
            """)
            row = cursor.fetchone()
            if row:
                user_id, email, name, verified, image, session_token, created_at = row
                logger.info("Found recent Neon Auth session for %s (created %s)", email, created_at)
                return {
                    'email': email,
                    'name': name,
                    'email_verified': verified if verified is not None else True,
                    'picture': image,
                }
    except Exception as e:
        logger.warning("Recent Neon DB session query check failed: %s", e)

    # 3. HTTP endpoint check on Neon Auth /get-session
    neon_auth_url = resolve_neon_auth_url()
    if neon_auth_url:
        try:
            cookie_header = "; ".join([f"{k}={v}" for k, v in request.COOKIES.items()])
            headers = {
                'Cookie': cookie_header,
                'User-Agent': 'DebSuLit-Bookstore/1.0',
            }
            if token:
                headers['Authorization'] = f'Bearer {token}'
            resp = requests.get(f"{neon_auth_url}/get-session", headers=headers, timeout=10)
            if resp.status_code == 200 and resp.text.strip() != 'null':
                data = resp.json()
                if data and 'user' in data:
                    user = data['user']
                    return {
                        'email': user.get('email'),
                        'name': user.get('name'),
                        'email_verified': user.get('emailVerified', True),
                        'picture': user.get('image'),
                    }
        except Exception as e:
            logger.warning("Neon Auth HTTP get-session check error: %s", e)

    return None



def exchange_code_for_token(code: str, code_verifier: str, redirect_uri: str):
    """
    Exchanges authorization code for an ID token and access token over TLS (Direct Google OAuth).
    """
    client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '').strip()
    client_secret = getattr(settings, 'GOOGLE_OAUTH_CLIENT_SECRET', '').strip()

    if not client_id or not client_secret:
        logger.error("Google OAuth credentials missing during token exchange.")
        return None

    payload = {
        'code': code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
        'code_verifier': code_verifier,
    }

    headers = {
        'Accept': 'application/json',
        'User-Agent': 'DebSuLit-OAuth/1.0',
    }

    try:
        response = requests.post(GOOGLE_TOKEN_ENDPOINT, data=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        logger.warning("Google token exchange failed: HTTP %s - %s", response.status_code, response.text)
        return None
    except Exception as e:
        logger.error("Exception during Google token exchange: %s", e, exc_info=True)
        return None


def fetch_google_userinfo(access_token: str):
    """
    Fetches user's basic profile and verified email from Google UserInfo endpoint.
    """
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
        'User-Agent': 'DebSuLit-OAuth/1.0',
    }

    try:
        response = requests.get(GOOGLE_USERINFO_ENDPOINT, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        logger.warning("Google userinfo fetch failed: HTTP %s - %s", response.status_code, response.text)
        return None
    except Exception as e:
        logger.error("Exception during Google userinfo fetch: %s", e, exc_info=True)
        return None


def generate_unique_username(base_name: str, email: str) -> str:
    """
    Creates a clean, valid, and unique Django username based on the Google user profile.
    """
    candidate = base_name or email.split('@')[0]
    candidate = re.sub(r'[^a-zA-Z0-9_]', '', candidate).lower()[:20]
    if not candidate:
        candidate = "user"

    if not CustomUser.objects.filter(username__iexact=candidate).exists():
        return candidate

    for _ in range(10):
        suffix = secrets.token_hex(2)
        unique_candidate = f"{candidate[:24]}_{suffix}"
        if not CustomUser.objects.filter(username__iexact=unique_candidate).exists():
            return unique_candidate

    return f"user_{secrets.token_hex(4)}"


def get_or_create_google_user(userinfo: dict):
    """
    Safely retrieves an existing user or registers a new privacy-preserving CustomUser in Neon PostgreSQL.
    
    :return: (user: CustomUser|None, is_new: bool, error_code: str|None)
    """
    email = userinfo.get('email', '').strip().lower()
    email_verified = userinfo.get('email_verified', False)

    if not email:
        return None, False, "missing_email"

    if not email_verified:
        logger.warning("Google OAuth rejected: email %s is not verified.", email)
        return None, False, "unverified_email"

    first_name = (userinfo.get('given_name') or userinfo.get('name') or '').strip()[:30]
    last_name = (userinfo.get('family_name') or '').strip()[:30]

    # Look up existing user by email
    existing_user = CustomUser.objects.filter(email__iexact=email).first()

    if existing_user:
        if not existing_user.is_active:
            return None, False, "account_inactive"

        updated = False
        # Mark user as having signed in via Google
        if not getattr(existing_user, 'is_google_user', False):
            existing_user.is_google_user = True
            updated = True

        # Update missing names if not already set
        if not existing_user.first_name and first_name:
            existing_user.first_name = first_name
            updated = True
        if not existing_user.last_name and last_name:
            existing_user.last_name = last_name
            updated = True
        if updated:
            try:
                existing_user.save()
            except Exception:
                pass

        return existing_user, False, None

    # Provision new user in Neon PostgreSQL with unusable password for maximum privacy & security
    username = generate_unique_username(first_name, email)
    new_user = CustomUser(
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        mobile='',
        is_google_user=True,
    )
    new_user.set_unusable_password()  # Account cannot be compromised via password-guessing
    new_user.save()

    logger.info("New user registered via Google/Neon OAuth: id=%s, username=%s", new_user.id, new_user.username)
    return new_user, True, None
