import logging
import random
import re
import string
import time
import razorpay
import razorpay.errors
from django.conf import settings
from django.db import connection, transaction
from django.db.models import Sum
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from . forms import MyRegFrm, StdRegFrm, MyChngFrm
from . models import CustomUser, Student, Category, Item, CartItem, Order
from . ratelimit import get_client_ip, check_rate_limit, record_failed_attempt, clear_failed_attempts
from . google_auth import (
    get_google_auth_url,
    verify_neon_session,
    exchange_code_for_token,
    fetch_google_userinfo,
    get_or_create_google_user,
)

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Health Check Endpoint (For UptimeRobot, Render, and Production Monitoring)
# -----------------------------------------------------------------------------
def health_check(request):
    """
    Health check endpoint designed for UptimeRobot, Render, and monitoring probes.
    Verifies database connectivity and app operational readiness.
    Returns HTTP 200 when all systems are healthy, or 503 if degraded.
    """
    db_status = "connected"
    is_healthy = True

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception as e:
        db_status = "disconnected"
        is_healthy = False
        logger.error("Health check database probe failed: %s", e, exc_info=True)

    payload = {
        "status": "healthy" if is_healthy else "unhealthy",
        "database": db_status,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "service": "DebSu-Lit Book Store",
        "version": "1.0.0",
    }
    if not is_healthy:
        payload["error"] = "Database service unavailable"

    status_code = 200 if is_healthy else 503
    return JsonResponse(payload, status=status_code)


# -----------------------------------------------------------------------------
# General Navigation Views
# -----------------------------------------------------------------------------
def home(request):
    categories = Category.objects.all().order_by('cat_name')
    allItem = Item.objects.all()
    return render(request, 'myapp/home.html', {'allItem': allItem, 'categories': categories})


def about(request):
    categories = Category.objects.all().order_by('cat_name')
    allItem = Item.objects.all()
    return render(request, 'myapp/about.html', {'allItem': allItem, 'categories': categories})


# -----------------------------------------------------------------------------
# User Account Settings
# -----------------------------------------------------------------------------
@login_required(login_url='/login')
def useraccount(request):
    categories = Category.objects.all().order_by('cat_name')
    allItem = Item.objects.all()

    if request.method == "POST":
        current_password = request.POST.get('current_password', '').strip()
        form = MyChngFrm(request.POST, instance=request.user)

        # If user has a set password, require it to authorize changes
        if request.user.has_usable_password():
            if not current_password:
                messages.error(request, 'Current account password is required to authorize profile changes.')
                return render(request, 'myapp/useraccount.html', {'form': form, 'allItem': allItem, 'categories': categories})

            if not request.user.check_password(current_password):
                messages.error(request, 'Incorrect current account password. Please enter your valid current password.')
                return render(request, 'myapp/useraccount.html', {'form': form, 'allItem': allItem, 'categories': categories})

        if form.is_valid():
            try:
                new_password = request.POST.get('new_password', '').strip()
                confirm_new_password = request.POST.get('confirm_new_password', '').strip()

                if new_password or confirm_new_password:
                    if not new_password:
                        messages.error(request, 'Please enter a new password.')
                        return render(request, 'myapp/useraccount.html', {'form': form, 'allItem': allItem, 'categories': categories})
                    if not confirm_new_password:
                        messages.error(request, 'Please confirm your new password.')
                        return render(request, 'myapp/useraccount.html', {'form': form, 'allItem': allItem, 'categories': categories})
                    if new_password != confirm_new_password:
                        messages.error(request, 'New password and password confirmation do not match.')
                        return render(request, 'myapp/useraccount.html', {'form': form, 'allItem': allItem, 'categories': categories})
                    if (len(new_password) < 8 or 
                            not re.search(r'[A-Z]', new_password) or 
                            not re.search(r'[a-z]', new_password) or 
                            not re.search(r'[0-9]', new_password) or 
                            not re.search(r'[@$!%*?&#^()_+=\-{}\[\]:;"\'<>,./]', new_password)):
                        messages.error(request, 'New password must have at least 8 characters, an uppercase letter (A-Z), a lowercase letter (a-z), a number (0-9), and a special character (e.g. @User123).')
                        return render(request, 'myapp/useraccount.html', {'form': form, 'allItem': allItem, 'categories': categories})
                    request.user.set_password(new_password)

                user = form.save()
                if new_password:
                    update_session_auth_hash(request, user)
                messages.success(request, 'Profile updated successfully!')
                return redirect('/useraccount')
            except Exception:
                logger.exception("Failed to update profile for user %s", request.user.username)
                messages.error(request, 'Profile could not be updated. Please check the entered details and try again.')
        else:
            messages.error(request, 'Please check and correct the highlighted errors in the form.')
    else:
        form = MyChngFrm(instance=request.user)

    return render(request, 'myapp/useraccount.html', {'form': form, 'allItem': allItem, 'categories': categories})


# -----------------------------------------------------------------------------
# Authentication Views (with Rate Limiting and Clear Error Separation)
# -----------------------------------------------------------------------------
def signIn(request):
    if request.user.is_authenticated:
        return redirect('/useraccount')

    if request.method == "POST":
        # Rate limit brute-force attempts: max 5 requests per 60 seconds per IP
        client_ip = get_client_ip(request)
        rate_key = f"login_ip:{client_ip}"
        allowed, remaining, retry_after = check_rate_limit(rate_key, limit=5, period_seconds=60)
        if not allowed:
            messages.error(request, f"Too many login attempts. Please wait {retry_after} second(s) before trying again.")
            return render(request, 'myapp/login.html')

        login_id = request.POST.get('username', '').strip()
        upass = request.POST.get('password', '')

        # Empty fields validation
        if not login_id and not upass:
            messages.error(request, "Please enter both your username/email and password.")
            return render(request, 'myapp/login.html')
        elif not login_id:
            messages.error(request, "Please enter your username or registered email address.")
            return render(request, 'myapp/login.html')
        elif not upass:
            messages.error(request, "Please enter your password.")
            return render(request, 'myapp/login.html', {'login_id': login_id})

        # Check user existence in database to give precise error feedback
        user_match = None
        if '@' in login_id:
            user_match = CustomUser.objects.filter(email__iexact=login_id).first()
        if not user_match:
            user_match = CustomUser.objects.filter(username__iexact=login_id).first()

        if not user_match:
            # Username / Email does not exist
            record_failed_attempt(f"login_fail:{client_ip}", period_seconds=300)
            messages.error(request, "Username or email not found. No account exists with these details.")
            return render(request, 'myapp/login.html', {'login_id': login_id})

        # User exists, verify password credentials
        user_obj = authenticate(username=user_match.username, password=upass)
        if user_obj is None:
            # Password is wrong
            record_failed_attempt(f"login_fail:{client_ip}", period_seconds=300)
            messages.error(request, "Incorrect password. Please verify your password and try again.")
            return render(request, 'myapp/login.html', {'login_id': login_id})

        if not user_obj.is_active:
            messages.error(request, "This account is currently deactivated. Please contact support.")
            return render(request, 'myapp/login.html', {'login_id': login_id})

        # Authentication successful
        clear_failed_attempts(f"login_fail:{client_ip}")
        clear_failed_attempts(rate_key)
        login(request, user_obj)
        messages.success(request, f"Welcome back, {user_obj.first_name or user_obj.username}!")
        return redirect('/useraccount')

    return render(request, 'myapp/login.html')


def signOut(request):
    logout(request)
    return redirect('/login')


# -----------------------------------------------------------------------------
# Google OAuth 2.0 Views (Privacy-Focused & Neon PostgreSQL Backed)
# -----------------------------------------------------------------------------
def google_login(request):
    """
    Initiates privacy-preserving Google OAuth 2.0 flow with state and PKCE parameters.
    """
    if request.user.is_authenticated:
        return redirect('/useraccount')

    client_ip = get_client_ip(request)
    allowed, remaining, retry_after = check_rate_limit(f"google_init:{client_ip}", limit=10, period_seconds=60)
    if not allowed:
        messages.error(request, f"Too many sign-in attempts. Please wait {retry_after} second(s).")
        return redirect('/login')

    auth_url = get_google_auth_url(request)
    if not auth_url:
        auth_err = request.session.pop('auth_error_message', None)
        if auth_err:
            messages.error(request, auth_err)
        else:
            messages.error(
                request,
                "Google sign-in is not configured yet. Please configure Neon Auth or set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET."
            )
        return redirect('/login')

    return redirect(auth_url)


def google_callback(request):
    """
    Processes the OAuth 2.0 callback from either Neon Auth or direct Google OAuth:
    1. Checks if Neon Auth session or token is present.
    2. Otherwise validates CSRF state and exchanges code for direct Google OAuth.
    3. Safely provisions or logs in the CustomUser in Neon PostgreSQL.
    """
    if request.user.is_authenticated:
        return redirect('/useraccount')

    # Check for cancellation or error from provider
    error = request.GET.get('error')
    if error:
        logger.info("Google OAuth returned error or user cancelled: %s", error)
        messages.warning(request, "Google sign-in was cancelled.")
        return redirect('/login')

    userinfo = None
    auth_mode = request.session.pop('auth_mode', None)

    # Path A: Neon Auth (Better Auth) Session Verification
    userinfo = verify_neon_session(request)

    # Path B: Direct Google OAuth (Code & PKCE Exchange)
    if not userinfo:
        incoming_state = request.GET.get('state', '').strip()
        session_state = request.session.pop('google_oauth_state', None)

        if incoming_state and session_state:
            if incoming_state != session_state:
                logger.warning("Google OAuth state mismatch: incoming=%s, session=%s", incoming_state, session_state)
                messages.error(request, "Security verification failed (state mismatch). Please try signing in again.")
                return redirect('/login')

            code = request.GET.get('code', '').strip()
            code_verifier = request.session.pop('google_oauth_code_verifier', None)
            redirect_uri = request.session.pop('google_oauth_redirect_uri', None)

            if code and code_verifier and redirect_uri:
                token_data = exchange_code_for_token(code, code_verifier, redirect_uri)
                if token_data and 'access_token' in token_data:
                    userinfo = fetch_google_userinfo(token_data['access_token'])

    if not userinfo:
        messages.error(request, "Authentication session expired or invalid. Please try signing in again.")
        return redirect('/login')

    # Provision or retrieve user from Neon database
    user, is_new, err_code = get_or_create_google_user(userinfo)

    if err_code == "account_inactive":
        messages.error(request, "This account is currently deactivated. Please contact support.")
        return redirect('/login')
    elif err_code == "unverified_email":
        messages.error(request, "Your Google email address is not verified. Please verify it with Google first.")
        return redirect('/login')
    elif not user:
        messages.error(request, "Unable to complete Google sign-in. Please try again.")
        return redirect('/login')

    # Log in user with Django standard ModelBackend
    login(request, user, backend='django.contrib.auth.backends.ModelBackend')

    if is_new:
        messages.success(request, f"Welcome to DebSu Lit, {user.first_name or user.username}! Your account has been created via Google.")
    else:
        messages.success(request, f"Welcome back, {user.first_name or user.username}!")

    next_url = request.session.pop('google_oauth_next_url', None) or '/useraccount'
    return redirect(next_url)




def signup(request):
    if request.user.is_authenticated:
        return redirect('/useraccount')

    if request.method == "POST":
        # Rate limit signup attempts: max 5 requests per 300 seconds (5 min) per IP
        client_ip = get_client_ip(request)
        rate_key = f"signup_ip:{client_ip}"
        allowed, remaining, retry_after = check_rate_limit(rate_key, limit=5, period_seconds=300)
        if not allowed:
            messages.error(request, f"Too many registration requests. Please wait {retry_after} second(s) before trying again.")
            return render(request, 'myapp/signup.html', {'frm': MyRegFrm(data=request.POST)})

        form = MyRegFrm(data=request.POST)
        if form.is_valid():
            try:
                form.save()
                messages.success(request, 'Account created successfully! Please sign in with your credentials.')
                return redirect('/login')
            except Exception:
                logger.exception("Failed to save new user registration")
                messages.error(request, 'Registration could not be completed. Please try again.')
        else:
            messages.error(request, 'Registration failed. Please check the highlighted errors below.')
    else:
        form = MyRegFrm()

    return render(request, 'myapp/signup.html', {'frm': form})


def forgotpassword(request):
    if request.method == "POST":
        # Rate limit password recovery attempts: max 5 requests per 300 seconds per IP
        client_ip = get_client_ip(request)
        rate_key = f"forgot_ip:{client_ip}"
        allowed, remaining, retry_after = check_rate_limit(rate_key, limit=5, period_seconds=300)
        if not allowed:
            messages.error(request, f"Too many reset requests. Please wait {retry_after} second(s) before trying again.")
            return render(request, 'myapp/forgotpassword.html')

        identity = request.POST.get('identity', '').strip()
        mobile = request.POST.get('mobile', '').strip()
        new_password = request.POST.get('new_password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        # Input completeness checks
        if not identity and not mobile:
            messages.error(request, 'Please enter both your username/email and registered mobile number.')
            return render(request, 'myapp/forgotpassword.html', {'identity': identity, 'mobile': mobile})

        if not identity:
            messages.error(request, 'Please enter your username or registered email address.')
            return render(request, 'myapp/forgotpassword.html', {'identity': identity, 'mobile': mobile})

        if not mobile:
            messages.error(request, 'Please enter your registered 10-digit mobile number.')
            return render(request, 'myapp/forgotpassword.html', {'identity': identity, 'mobile': mobile})

        # Find user by username or email
        user_match = None
        if '@' in identity:
            user_match = CustomUser.objects.filter(email__iexact=identity).first()
        if not user_match:
            user_match = CustomUser.objects.filter(username__iexact=identity).first()

        if not user_match:
            messages.error(request, 'Username or email not found. No registered account exists with these details.')
            return render(request, 'myapp/forgotpassword.html', {'identity': identity, 'mobile': mobile})

        if getattr(user_match, 'mobile', '') != mobile:
            messages.error(request, 'The mobile number provided does not match our records for this account.')
            return render(request, 'myapp/forgotpassword.html', {'identity': identity, 'mobile': mobile})

        if not new_password and not confirm_password:
            messages.error(request, 'Please enter and confirm your new password.')
            return render(request, 'myapp/forgotpassword.html', {'identity': identity, 'mobile': mobile})

        if not new_password:
            messages.error(request, 'Please enter a new password.')
            return render(request, 'myapp/forgotpassword.html', {'identity': identity, 'mobile': mobile})

        if not confirm_password:
            messages.error(request, 'Please confirm your new password.')
            return render(request, 'myapp/forgotpassword.html', {'identity': identity, 'mobile': mobile})

        if new_password != confirm_password:
            messages.error(request, 'New password and password confirmation do not match.')
            return render(request, 'myapp/forgotpassword.html', {'identity': identity, 'mobile': mobile})

        # Validate password strength
        if (len(new_password) < 8 or 
                not re.search(r'[A-Z]', new_password) or 
                not re.search(r'[a-z]', new_password) or 
                not re.search(r'[0-9]', new_password) or 
                not re.search(r'[@$!%*?&#^()_+=\-{}\[\]:;"\'<>,./]', new_password)):
            messages.error(request, 'Password must be at least 8 characters long and contain at least one uppercase letter (A-Z), one lowercase letter (a-z), one number (0-9), and one special character (e.g. @User123).')
            return render(request, 'myapp/forgotpassword.html', {'identity': identity, 'mobile': mobile})

        # Update password
        user_match.set_password(new_password)
        user_match.save()
        clear_failed_attempts(rate_key)
        messages.success(request, 'Your password has been reset successfully! Please log in with your new password.')
        return redirect('/login')

    return render(request, 'myapp/forgotpassword.html')


# -----------------------------------------------------------------------------
# Catalog & Book Views
# -----------------------------------------------------------------------------
def orders(request):
    return render(request, 'myapp/orders.html')


def shoppingcart(request):
    return render(request, 'myapp/shoppingcart.html')


def featured(request):
    return render(request, 'myapp/featured.html')


def arrivals(request, id):
    categories = Category.objects.all().order_by('cat_name')
    allItem = Item.objects.filter(category=id)
    return render(request, 'myapp/arrivals.html', {'allItem': allItem, 'categories': categories})


def featuresbook1(request, item_id):
    item = get_object_or_404(Item.objects.select_related('category'), id=item_id)
    in_cart_qty = 0
    if request.user.is_authenticated:
        cart_entry = CartItem.objects.filter(item=item, user=request.user).first()
        if cart_entry:
            in_cart_qty = cart_entry.quantity
    return render(request, 'myapp/featuresbook1.html', {
        'item': item,
        'in_cart_qty': in_cart_qty,
        'in_cart': in_cart_qty > 0,
    })


# -----------------------------------------------------------------------------
# Cart & Checkout Operations
# -----------------------------------------------------------------------------
def add_to_cart(request, item_id):
    if not request.user.is_authenticated:
        if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.POST.get('ajax') == '1' or request.GET.get('ajax') == '1':
            return JsonResponse({'status': 'error', 'message': 'Please log in to add items to your cart.', 'redirect': '/login'}, status=401)
        return redirect('/login')

    item = get_object_or_404(Item, id=item_id)
    cart_item, created = CartItem.objects.get_or_create(item=item, user=request.user)

    try:
        qty_param = int(request.POST.get('quantity') or request.GET.get('quantity') or 1)
    except (ValueError, TypeError):
        qty_param = 1

    qty_param = max(1, min(99, qty_param))

    action = request.POST.get('action') or request.GET.get('action')
    if action == 'set':
        cart_item.quantity = qty_param
    elif created:
        cart_item.quantity = qty_param
    else:
        cart_item.quantity += qty_param

    cart_item.save()

    total_count = CartItem.objects.filter(user=request.user).aggregate(total=Sum('quantity'))['total'] or 0

    if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.POST.get('ajax') == '1' or request.GET.get('ajax') == '1':
        return JsonResponse({
            'status': 'success',
            'cart_count': total_count,
            'item_quantity': cart_item.quantity,
            'item_id': item.id,
            'message': f'"{item.name}" added to cart!'
        })

    if request.POST.get('buy_now') == '1' or request.GET.get('buy_now') == '1':
        return redirect('/cart')

    return redirect('/cart')


def buy_now(request, item_id):
    if not request.user.is_authenticated:
        return redirect('loginpage')

    item = get_object_or_404(Item, id=item_id)
    cart_item, created = CartItem.objects.get_or_create(item=item, user=request.user)

    try:
        qty_param = int(request.POST.get('quantity') or request.GET.get('quantity') or 1)
    except (ValueError, TypeError):
        qty_param = 1

    qty_param = max(1, min(99, qty_param))
    cart_item.quantity = max(cart_item.quantity, qty_param)
    cart_item.save()

    return redirect('/cart')


@login_required(login_url='/login')
def view_cart(request):
    cart_items = CartItem.objects.filter(user=request.user).select_related('item', 'item__category')
    total_price = sum(int(ci.item.price) * int(ci.quantity) for ci in cart_items)
    return render(request, 'myapp/cart.html', {
        'cart_items': cart_items,
        'total_price': total_price,
        'saved_user': request.user
    })


@login_required(login_url='/login')
def remove_cart(request, id):
    cart_item = CartItem.objects.filter(id=id, user=request.user).first()
    if cart_item:
        cart_item.delete()
    return redirect('/cart')


# -----------------------------------------------------------------------------
# Razorpay Payment Gateway Integration (with Rate Limiting & Anti-Tamper)
# -----------------------------------------------------------------------------
@login_required(login_url='/login')
def initiate_payment(request):
    if request.method == "POST":
        # Rate limit payment orders: max 10 requests per 60 seconds per user / IP
        client_ip = get_client_ip(request)
        rate_key = f"payment_init:{request.user.id}:{client_ip}"
        allowed, remaining, retry_after = check_rate_limit(rate_key, limit=10, period_seconds=60)
        if not allowed:
            return JsonResponse({
                "error": f"Too many payment requests. Please wait {retry_after} second(s) before trying again."
            }, status=429)

        address = request.POST.get('address', '').strip()
        if not address:
            return JsonResponse({"error": "Delivery address is required."}, status=400)

        # Optionally save address to user profile
        if request.POST.get('save_to_profile') == 'true':
            addr_line1 = request.POST.get('addr_line1', '').strip()
            addr_line2 = request.POST.get('addr_line2', '').strip()
            city = request.POST.get('addr_city', '').strip()
            state = request.POST.get('addr_state', '').strip()
            pincode = request.POST.get('addr_pincode', '').strip()
            if addr_line1:
                request.user.address_line1 = addr_line1
            if addr_line2:
                request.user.address_line2 = addr_line2
            if city:
                request.user.city = city
            if state:
                request.user.state = state
            if pincode:
                request.user.pincode = pincode
            try:
                request.user.save()
            except Exception:
                pass

        cart_items = CartItem.objects.filter(user=request.user).select_related('item')
        if not cart_items.exists():
            return JsonResponse({"error": "Your cart is empty."}, status=400)

        # Server-side calculation of total amount: never rely on client input
        total_price = sum(int(item.item.price) * int(item.quantity) for item in cart_items)
        if total_price <= 0:
            return JsonResponse({"error": "Invalid order amount."}, status=400)

        amount_in_paise = int(total_price * 100)

        if not settings.RAZORPAY_API_KEY or not settings.RAZORPAY_API_SECRET:
            logger.error("Razorpay API credentials are not configured in settings.")
            return JsonResponse({"error": "Payment service is currently unavailable. Please try again later."}, status=500)

        client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
        receipt_id = f"rcpt_{request.user.id}_{int(time.time())}"
        payment_data = {
            "amount": amount_in_paise,
            "currency": "INR",
            "receipt": receipt_id,
            "notes": {
                "user_id": str(request.user.id),
                "username": request.user.username,
            },
        }

        try:
            order = client.order.create(data=payment_data)
        except Exception as e:
            logger.error("Failed to initiate order with Razorpay: %s", e, exc_info=True)
            return JsonResponse({"error": "Failed to initiate payment. Please try again later."}, status=500)

        # Store pending order details in session to verify against during callback
        request.session['pending_order_address'] = address
        request.session['pending_razorpay_order_id'] = order["id"]
        request.session['pending_order_amount'] = amount_in_paise

        user_name = request.user.get_full_name() or request.user.username
        user_email = request.user.email or ""
        user_contact = getattr(request.user, 'mobile', '') or ""

        response_data = {
            "id": order["id"],
            "amount": order["amount"],
            "currency": order["currency"],
            "key": settings.RAZORPAY_API_KEY,
            "name": "DebSu Lit Book Store",
            "description": "Payment for Book Purchase",
            "prefill": {
                "name": user_name,
                "email": user_email,
                "contact": user_contact,
            },
        }

        return JsonResponse(response_data)

    return redirect('/cart')


@login_required(login_url='/login')
def verify_payment(request):
    if request.method == "POST":
        # Rate limit payment verifications: max 10 requests per 60 seconds per user / IP
        client_ip = get_client_ip(request)
        rate_key = f"payment_verify:{request.user.id}:{client_ip}"
        allowed, remaining, retry_after = check_rate_limit(rate_key, limit=10, period_seconds=60)
        if not allowed:
            return JsonResponse({
                "status": "failure",
                "message": f"Too many verification requests. Please wait {retry_after} second(s)."
            }, status=429)

        razorpay_order_id = request.POST.get("razorpay_order_id", "").strip()
        razorpay_payment_id = request.POST.get("razorpay_payment_id", "").strip()
        razorpay_signature = request.POST.get("razorpay_signature", "").strip()
        address = request.POST.get("address", "").strip() or request.session.get("pending_order_address", "")

        if not (razorpay_order_id and razorpay_payment_id and razorpay_signature):
            return JsonResponse({"status": "failure", "message": "Missing payment verification parameters."}, status=400)

        # Anti-replay / cross-user check: ensure order ID matches pending session
        session_order_id = request.session.get("pending_razorpay_order_id")
        if session_order_id and session_order_id != razorpay_order_id:
            logger.warning("Session order ID %s mismatch with incoming order ID %s", session_order_id, razorpay_order_id)
            return JsonResponse({"status": "failure", "message": "Order session mismatch."}, status=400)

        client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
        params_dict = {
            "razorpay_order_id": razorpay_order_id,
            "razorpay_payment_id": razorpay_payment_id,
            "razorpay_signature": razorpay_signature,
        }

        # Cryptographically verify that payment was authorized by Razorpay
        try:
            client.utility.verify_payment_signature(params_dict)
        except razorpay.errors.SignatureVerificationError as e:
            logger.warning("Payment signature verification failed for order %s: %s", razorpay_order_id, e)
            return JsonResponse({"status": "failure", "message": "Payment signature verification failed."}, status=400)
        except Exception as e:
            logger.error("Unexpected error during payment verification for order %s: %s", razorpay_order_id, e, exc_info=True)
            return JsonResponse({"status": "failure", "message": "Payment verification failed. Please try again or contact support."}, status=400)

        # Payment verified: generate unique random order ID and record order atomically
        random_order_number = random.randint(100000, 999999)
        generated_order_id = f"DSL-ORD-{random_order_number}"

        with transaction.atomic():
            cart_items = CartItem.objects.filter(user=request.user).select_related('item')
            for cart in cart_items:
                Order.objects.create(
                    order_id=generated_order_id,
                    user=request.user,
                    item=cart.item,
                    quantity=cart.quantity,
                    payment_status="success",
                    payment_id=razorpay_payment_id,
                    address=address,
                )
            cart_items.delete()

        # Clean up session keys
        request.session.pop("pending_order_address", None)
        request.session.pop("pending_razorpay_order_id", None)
        request.session.pop("pending_order_amount", None)
        request.session["last_order_id"] = generated_order_id

        return JsonResponse({"status": "success", "message": "Payment verified successfully!", "order_id": generated_order_id})

    return JsonResponse({"status": "failure", "message": "Invalid request method."}, status=405)


def payment_success(request):
    return render(request, "myapp/payment_success.html")


def payment_failed(request):
    return render(request, "myapp/payment_failed.html")


@login_required(login_url='/login')
def myOrders(request):
    allord = Order.objects.filter(user=request.user).select_related('item', 'item__category').order_by('-date_ordered', '-id')
    return render(request, 'myapp/viewOrders.html', {'orderItems': allord})


# -----------------------------------------------------------------------------
# Protected Administrative / Student Views (Staff / Admin Authorization)
# -----------------------------------------------------------------------------
def is_admin_or_staff(user):
    return user.is_authenticated and (user.is_staff or user.is_superuser)


@user_passes_test(is_admin_or_staff, login_url='/login')
def stdReg(request):
    if request.POST:
        form = StdRegFrm(data=request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Registration is Successful')
        else:
            messages.error(request, 'Registration is Unsuccessful')
    else:
        form = StdRegFrm()
    context = {'form': form}
    return render(request, 'myapp/stdReg.html', context)


@user_passes_test(is_admin_or_staff, login_url='/login')
def stdList(request):
    allstd = Student.objects.all()
    return render(request, 'myapp/stdShow.html', {'allstd': allstd})


@user_passes_test(is_admin_or_staff, login_url='/login')
def stdDel(request, id):
    std = get_object_or_404(Student, id=id)
    std.delete()
    messages.success(request, 'Student Details Removed Successfully')
    return redirect('/stdlist')


@user_passes_test(is_admin_or_staff, login_url='/login')
def stdUpd(request, id):
    std = get_object_or_404(Student, id=id)
    form = StdRegFrm(request.POST or None, instance=std)
    if form.is_valid():
        try:
            form.save()
            messages.success(request, 'Student Details Updated Successfully')
        except Exception:
            logger.exception("Failed to update student details for ID %s", id)
            messages.error(request, 'Student Details Not Updated Successfully')
        return redirect('/stdlist')
    return render(request, 'myapp/stdUpd.html', {'form': form})


@user_passes_test(is_admin_or_staff, login_url='/login')
def stdAdmin(request):
    allfeatured = Category.objects.all()
    return render(request, 'myapp/stdAdmin.html', {'allfeatured': allfeatured})


def terms(request):
    return render(request, 'myapp/terms.html')


def privacy_policy(request):
    return render(request, 'myapp/privacy.html')


def refund_policy(request):
    return render(request, 'myapp/refund.html')


def shipping_policy(request):
    return render(request, 'myapp/shipping.html')


def contact(request):
    return render(request, 'myapp/contact.html')


def pricing(request):
    return render(request, 'myapp/pricing.html')
