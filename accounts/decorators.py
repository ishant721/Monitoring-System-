# accounts/decorators.py

from functools import wraps
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages
from django.conf import settings
from .models import CustomUser

# --- No changes needed to this decorator ---
def otp_session_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        otp_user_id = request.session.get('otp_user_id')
        otp_flow = request.session.get('otp_flow')
        if not otp_user_id or not otp_flow:
            messages.error(request, "Your session has expired or is invalid. Please start the process again.")
            return redirect('accounts:login')
        try:
            request.otp_user = CustomUser.objects.get(pk=otp_user_id)
        except CustomUser.DoesNotExist:
            messages.error(request, "User for verification not found.")
            if 'otp_user_id' in request.session: del request.session['otp_user_id']
            if 'otp_flow' in request.session: del request.session['otp_flow']
            return redirect('accounts:login')
        return view_func(request, *args, **kwargs)
    return _wrapped_view

# --- No changes needed to this decorator factory ---
def role_required(allowed_roles=[]):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect(settings.LOGIN_URL)
            if not isinstance(request.user, CustomUser) or request.user.role not in allowed_roles:
                messages.error(request, "You do not have permission to view this page.")
                return redirect('accounts:dashboard')
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

# --- No changes needed to these decorators ---
def superadmin_required(view_func):
    return role_required([CustomUser.SUPERADMIN])(view_func)

def admin_required(view_func):
    return role_required([CustomUser.ADMIN, CustomUser.SUPERADMIN])(view_func)

# --- ADD THIS NEW DECORATOR for the agent download page ---
def user_required(view_func):
    """
    Decorator for views that are only accessible to users with the 'USER' role.
    """
    return role_required([CustomUser.USER])(view_func)