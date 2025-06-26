# accounts/views.py
import json # <--- ADD THIS LINE
import traceback
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib import messages
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta 
import logging


logger = logging.getLogger(__name__)


from .forms import (
    CustomUserCreationForm, CustomAuthenticationForm, OTPVerificationForm,
    PasswordResetRequestForm, SetNewPasswordForm, 
    SuperadminAddAdminForm, AdminAddUserForm,
    SuperadminManageAdminAccessForm, 
    AdminTrialExtensionRequestForm
)
from .models import CustomUser
from .utils import (
    send_registration_otp_email, send_password_reset_otp_email,
    send_admin_registration_approval_request_email,
    send_user_registration_approval_request_email,
    send_user_account_status_email,
    send_admin_access_status_email,
    send_admin_access_expiry_warning_email,
    send_trial_extension_request_to_superadmins_email,
    send_admin_trial_extension_status_email
)
from .decorators import otp_session_required, superadmin_required, admin_required

from monitor_app.models import Agent

from django.contrib.auth.decorators import login_required
from .decorators import user_required

from channels.layers import get_channel_layer # <-- ADD THIS
from asgiref.sync import async_to_sync       # <-- ADD THIS
from mail_monitor.models import EmailAccount  # <-- ADD THIS

from mail_monitor.models import CompanyEmailConfig

# --- Authentication Lifecycle Views (All UNCHANGED) ---

def register_view(request):
    if request.user.is_authenticated and isinstance(request.user, CustomUser):
        return redirect(settings.LOGIN_REDIRECT_URL)
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            send_registration_otp_email(user, request)
            request.session['otp_user_id'] = user.id
            request.session['otp_flow'] = 'registration'
            messages.success(request, 'Registration successful! Please check your email for an OTP.')
            return redirect('accounts:verify_otp')
    else:
        form = CustomUserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})

@otp_session_required
def verify_otp_view(request):
    user = request.otp_user
    otp_flow = request.session.get('otp_flow')

    if not otp_flow:
        messages.error(request, "Invalid OTP attempt or session expired.")
        return redirect('accounts:login')
    
    if otp_flow == 'registration' and user.is_email_verified:
        messages.info(request, "Your email is already verified.")
        request.session['last_otp_verified_user_id_for_pending_page'] = user.id
        if 'otp_user_id' in request.session: del request.session['otp_user_id']
        if 'otp_flow' in request.session: del request.session['otp_flow']
        return redirect('accounts:registration_pending_approval')

    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']
            if user.email_otp == otp and user.is_otp_valid():
                user.email_otp = None 
                user.otp_created_at = None
                
                if otp_flow == 'registration':
                    user.is_email_verified = True
                    user.save(update_fields=['is_email_verified', 'email_otp', 'otp_created_at'])
                    messages.success(request, 'Email verified successfully!')
                    
                    if user.role == CustomUser.ADMIN:
                        send_admin_registration_approval_request_email(user, request)
                    elif user.role == CustomUser.USER and user.company_admin:
                        send_user_registration_approval_request_email(user, user.company_admin, request)
                    
                    request.session['last_otp_verified_user_id_for_pending_page'] = user.id
                    if 'otp_user_id' in request.session: del request.session['otp_user_id']
                    if 'otp_flow' in request.session: del request.session['otp_flow']
                    return redirect('accounts:registration_pending_approval')
                
                elif otp_flow == 'password_reset':
                    user.save(update_fields=['email_otp', 'otp_created_at'])
                    messages.success(request, 'OTP verified. Please set your new password.')
                    return redirect('accounts:set_new_password')
            else:
                messages.error(request, 'Invalid or expired OTP. Please try again or request a new one.')
    else:
        form = OTPVerificationForm()
    
    purpose = "Account Email Verification" if otp_flow == 'registration' else "Password Reset"
    return render(request, 'accounts/verify_otp.html', {'form': form, 'verification_type': 'Email OTP', 'user_email': user.email, 'purpose': purpose, 'otp_flow': otp_flow})

def registration_pending_approval_view(request):
    user_id = request.session.pop('last_otp_verified_user_id_for_pending_page', None)
    if not user_id:
        messages.warning(request, "Session expired or OTP verification not completed. Please start over.")
        return redirect('accounts:register')
    try:
        user = CustomUser.objects.get(pk=user_id)
    except CustomUser.DoesNotExist:
        messages.error(request, "User context not found for pending approval page. Please register again.")
        return redirect('accounts:register')
    
    message_text = "Your account registration is complete and your email has been verified. "
    if user.role == CustomUser.ADMIN:
        message_text += "Your account is now awaiting approval from a Superadmin. They have been notified."
    elif user.role == CustomUser.USER:
        if user.company_admin:
             message_text += f"Your account is now awaiting approval from your company Admin ({user.company_admin.get_full_name()}). They have been notified."
        else:
            message_text += "Your account is awaiting assignment and approval. Please contact support if you don't hear back."
    return render(request, 'accounts/registration_pending_approval.html', {'message': message_text})

@otp_session_required
def resend_registration_email_otp_view(request):
    user = request.otp_user
    if request.session.get('otp_flow') != 'registration':
        messages.error(request,"Invalid request for resending registration OTP.")
        return redirect('accounts:register')
    
    if user.is_email_verified:
        messages.info(request,"Your email address is already verified.")
        return redirect('accounts:registration_pending_approval')

    if send_registration_otp_email(user, request):
        messages.success(request,"A new OTP has been sent to your email address.")
    else:
        messages.error(request,"Failed to send a new OTP. Please try again in a few moments.")
    return redirect('accounts:verify_otp')

def password_reset_request_view(request):
    if request.user.is_authenticated: return redirect(settings.LOGIN_REDIRECT_URL)
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = CustomUser.objects.get(email__iexact=email, is_active=True, is_email_verified=True)
                if send_password_reset_otp_email(user, request):
                    request.session['otp_user_id'] = user.id
                    request.session['otp_flow'] = 'password_reset'
                    messages.success(request, 'An OTP has been sent to your email to reset your password.')
                    return redirect('accounts:verify_otp')
                else:
                    messages.error(request, "Failed to send password reset OTP. Please try again.")
            except CustomUser.DoesNotExist:
                messages.info(request, 'If an account with that email exists and meets the criteria, an OTP has been sent.')
            return redirect('accounts:password_reset_request')
    else:
        form = PasswordResetRequestForm()
    return render(request, 'accounts/password_reset_request_form.html', {'form': form})

@otp_session_required
def set_new_password_view(request):
    user = request.otp_user
    if request.session.get('otp_flow') != 'password_reset':
        messages.error(request,"Invalid password reset session. Please request a new OTP.")
        if 'otp_user_id' in request.session: del request.session['otp_user_id']
        if 'otp_flow' in request.session: del request.session['otp_flow']
        return redirect('accounts:password_reset_request')
    if request.method == 'POST':
        form = SetNewPasswordForm(user, request.POST)
        if form.is_valid():
            form.save()
            user.email_otp = None 
            user.otp_created_at = None
            user.save(update_fields=['email_otp','otp_created_at'])
            if 'otp_user_id' in request.session: del request.session['otp_user_id']
            if 'otp_flow' in request.session: del request.session['otp_flow']
            messages.success(request,'Your password has been reset successfully. You can now log in.')
            return redirect('accounts:login')
    else:
        form = SetNewPasswordForm(user)
    return render(request, 'accounts/set_new_password_form.html', {'form': form})

def login_view(request):
    if request.user.is_authenticated and isinstance(request.user, CustomUser):
        return redirect(settings.LOGIN_REDIRECT_URL)
    elif request.user.is_authenticated:
        auth_logout(request)
        messages.info(request,"You have been logged out. Please log in using the application form.")
    
    form_to_render = CustomAuthenticationForm(request)
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user_to_login = form.get_user()
            
            from django.contrib.sessions.models import Session
            current_session_key = request.session.session_key 
            for session_obj in Session.objects.filter(expire_date__gte=timezone.now()):
                if session_obj.get_decoded().get('_auth_user_id') == str(user_to_login.pk) and session_obj.session_key != current_session_key:
                    session_obj.delete()
            
            auth_login(request, user_to_login)
            response = redirect(settings.LOGIN_REDIRECT_URL)
            messages.success(request,f'Welcome back, {user_to_login.get_full_name()}!')
            return response
        else:
            form_to_render = form
    return render(request, 'accounts/login.html', {'form': form_to_render})

@login_required
def logout_view(request):
    auth_logout(request)
    response = redirect('accounts:login')
    messages.info(request,'You have been successfully logged out.')
    return response

# --- Dashboard & User Management Views (Core logic is UNCHANGED) ---

@login_required
def dashboard_view(request):
    if not isinstance(request.user, CustomUser):
        messages.error(request,"Authentication error. Please log in again."); auth_logout(request); return redirect('accounts:login')
    # MODIFIED: A USER will now go to a simplified dashboard.
    if request.user.role == CustomUser.SUPERADMIN: return redirect('accounts:superadmin_dashboard')
    elif request.user.role == CustomUser.ADMIN: return redirect('accounts:admin_dashboard')
    elif request.user.role == CustomUser.USER: return redirect('accounts:user_dashboard')
    messages.error(request,"User role not recognized."); auth_logout(request); return redirect('accounts:login')

@login_required
@superadmin_required
def superadmin_dashboard_view(request):
    admins_query = CustomUser.objects.filter(role=CustomUser.ADMIN).order_by('email')
    admin_details_list = []
    for admin in admins_query:
        admin_details_list.append({
            'user': admin,
            'current_users': admin.get_current_approved_users_count(),
            'access_form': SuperadminManageAdminAccessForm(instance=admin, prefix=f"access_form_{admin.pk}"),
            'is_admin_access_active': admin.is_admin_access_active,
            'access_days_remaining': admin.access_days_remaining,
        })
    pending_admins_to_approve = CustomUser.objects.filter(role=CustomUser.ADMIN, is_active=False, approved_by__isnull=True, is_email_verified=True).order_by('date_joined')
    add_admin_form = SuperadminAddAdminForm(prefix="add_new_admin_form")
    context = {'admin_details_list': admin_details_list, 'pending_admins_to_approve': pending_admins_to_approve, 'add_new_admin_form': add_admin_form}
    return render(request, 'accounts/superadmin_dashboard.html', context)

@login_required
@superadmin_required
def superadmin_add_admin_view(request):
    if request.method == 'POST':
        form = SuperadminAddAdminForm(request.POST, prefix="add_new_admin_form")
        if form.is_valid():
            new_admin = form.save(commit=True, added_by_superadmin=request.user)
            access_ends_str = new_admin.access_ends_at.strftime('%B %d, %Y') if new_admin.access_ends_at else 'Indefinite'
            messages.success(request, f"Admin '{new_admin.email}' created. Type: {new_admin.get_admin_account_type_display()}. Access ends: {access_ends_str}.")
            send_admin_access_status_email(new_admin, request, triggered_by_superadmin=request.user)
            return redirect('accounts:superadmin_dashboard')
        else:
            for field, errors in form.errors.items(): 
                messages.error(request, f"Add Admin Error - {form.fields.get(field, type('obj', (object,), {'label': field.replace('_',' ').title()})()).label}: {'; '.join(errors)}")
    return redirect('accounts:superadmin_dashboard')

@login_required
@superadmin_required
def approve_admin_view(request, user_id):
    admin_to_approve = get_object_or_404(CustomUser, pk=user_id, role=CustomUser.ADMIN)
    if admin_to_approve.is_active and admin_to_approve.approved_by: 
        messages.warning(request, f"Admin {admin_to_approve.email} is already approved and active.")
    elif not admin_to_approve.is_email_verified: 
        messages.error(request, f"Admin {admin_to_approve.email}'s email is not verified. Cannot approve.")
    else:
        admin_to_approve.is_active = True
        admin_to_approve.approved_by = request.user
        if admin_to_approve.admin_account_type == CustomUser.AdminAccountType.NONE:
             admin_to_approve.admin_account_type = CustomUser.AdminAccountType.TRIAL 
             default_trial_days = getattr(settings, 'DEFAULT_ADMIN_TRIAL_DAYS', 7)
             admin_to_approve.access_ends_at = timezone.now() + timedelta(days=default_trial_days)
             admin_to_approve.max_allowed_users = admin_to_approve.max_allowed_users if admin_to_approve.max_allowed_users is not None else 0
             admin_to_approve.access_granted_by = request.user
             messages.info(request, f"Admin {admin_to_approve.email} approved and set to a default {default_trial_days}-day trial. Please review their access settings.")
        
        admin_to_approve.save()
        messages.success(request, f"Admin {admin_to_approve.email} has been approved and activated.")
        send_admin_access_status_email(admin_to_approve, request, triggered_by_superadmin=request.user)
    return redirect('accounts:superadmin_dashboard')

@login_required
@superadmin_required
def superadmin_manage_admin_access_view(request, admin_id):
    admin_user = get_object_or_404(CustomUser, pk=admin_id, role=CustomUser.ADMIN)
    form_prefix = f"access_form_{admin_user.pk}"
    original_trial_extension_requested = admin_user.trial_extension_requested

    if request.method == 'POST':
        form = SuperadminManageAdminAccessForm(request.POST, instance=admin_user, prefix=form_prefix)
        if form.is_valid():
            admin_instance_to_save = form.save(commit=False)
            admin_instance_to_save.access_granted_by = request.user
            new_duration_days = form.cleaned_data.get('new_access_duration_days')
            
            if admin_instance_to_save.admin_account_type == CustomUser.AdminAccountType.EXPIRED:
                admin_instance_to_save.access_ends_at = timezone.now()
            elif new_duration_days is not None and new_duration_days >= 0:
                admin_instance_to_save.access_ends_at = timezone.now() + timedelta(days=new_duration_days)
            elif admin_instance_to_save.admin_account_type == CustomUser.AdminAccountType.SUBSCRIBED and new_duration_days is None:
                admin_instance_to_save.access_ends_at = None
            
            if admin_instance_to_save.admin_account_type != CustomUser.AdminAccountType.TRIAL:
                admin_instance_to_save.trial_extension_requested = False
                admin_instance_to_save.trial_extension_reason = None
            
            admin_instance_to_save.save()
            messages.success(request, f"Access settings for {admin_user.email} updated successfully.")
            send_admin_access_status_email(admin_instance_to_save, request, triggered_by_superadmin=request.user)

            if original_trial_extension_requested and not admin_instance_to_save.trial_extension_requested:
                is_extension_approved = admin_instance_to_save.admin_account_type == CustomUser.AdminAccountType.TRIAL and admin_instance_to_save.is_admin_access_active
                send_admin_trial_extension_status_email(admin_instance_to_save, is_extension_approved, request.user, "Your trial status has been updated.", request)
            
            return redirect('accounts:superadmin_dashboard')
        else:
            for field, errors in form.errors.items(): 
                messages.error(request, f"Update Access Error ({admin_user.email}) - {form.fields.get(field, type('obj', (object,), {'label': field.replace('_',' ').title()})()).label}: {'; '.join(errors)}")    
    return redirect('accounts:superadmin_dashboard')

@login_required
@admin_required 
def admin_dashboard_view(request):
    """
    The main dashboard for an Admin. It displays their own account status,
    user management tables, and links to other dashboards.
    
    This view now also checks if the admin has configured the email monitoring
    settings to display the correct card in the template.
    """
    viewer = request.user
    
    # Initialize the context dictionary. 
    # The is_superadmin_view flag can be used in the template to show/hide certain elements.
    context = {
        'is_superadmin_view': viewer.role == CustomUser.SUPERADMIN
    }

    # This block gathers all the data specific to an Admin's account
    if viewer.role == CustomUser.ADMIN:
        
        # --- NEW LOGIC TO CHECK EMAIL CONFIGURATION ---
        # This checks if a CompanyEmailConfig object linked to this admin exists in the database.
        # The .exists() method is very efficient as it doesn't retrieve the object, just checks for its presence.
        has_email_config = CompanyEmailConfig.objects.filter(admin=viewer).exists()
        
        # --- Existing logic for account expiry warnings ---
        days_left = viewer.access_days_remaining
        warning_days = getattr(settings, 'ADMIN_ACCESS_EXPIRY_WARNING_DAYS', 3)
        impending_expiry_notification = None
        if days_left is not None and 0 <= days_left <= warning_days:
            expiry_date_str = viewer.access_ends_at.strftime('%B %d, %Y')
            impending_expiry_notification = {
                'type': 'warning', 
                'text': f"Access Alert: Your account will expire in {days_left} day(s) on {expiry_date_str}."
            }

        # --- Existing logic for trial extension form ---
        trial_extension_form = None
        if viewer.admin_account_type == CustomUser.AdminAccountType.TRIAL and not viewer.trial_extension_requested:
            if days_left is not None and days_left <= getattr(settings, 'ADMIN_TRIAL_EXTENSION_REQUEST_WINDOW_DAYS', 7):
                trial_extension_form = AdminTrialExtensionRequestForm()

        # Update the context with all admin-specific data
        context.update({
            'is_admin_role_view': True,
            'admin_user_instance': viewer,
            'impending_expiry_notification': impending_expiry_notification,
            'trial_extension_form_for_admin': trial_extension_form,
            'can_approve_more_flag': viewer.can_approve_more_users(),
            'current_approved_count': viewer.get_current_approved_users_count(),
            'max_users_limit': viewer.max_allowed_users,
            'add_user_form': AdminAddUserForm(prefix="add_new_user_by_admin_form") if viewer.can_approve_more_users() else None,
            'has_email_config': has_email_config, # <-- Passing the new flag to the template
        })
    
    # --- Common logic for both Admin and Superadmin ---
    # This section fetches the lists of users to be displayed in the tables.
    
    # If the viewer is a regular Admin, filter to only their company's users.
    # If the viewer is a Superadmin, this filter is empty, so they see all users.
    user_filter = {'company_admin': viewer} if viewer.role == CustomUser.ADMIN else {}
    
    context['pending_users'] = CustomUser.objects.filter(
        role=CustomUser.USER, 
        is_active=False, 
        approved_by__isnull=True, 
        is_email_verified=True, 
        **user_filter
    ).select_related('company_admin')
    
    context['managed_users'] = CustomUser.objects.filter(
        role=CustomUser.USER, 
        **user_filter
    ).select_related('approved_by', 'company_admin').order_by('-is_active', 'email')
    
    # Render the final template with the complete context
    return render(request, 'accounts/admin_dashboard.html', context)


@login_required
@admin_required 
def admin_request_trial_extension_view(request):
    admin_user = request.user
    if not (admin_user.role == CustomUser.ADMIN and admin_user.admin_account_type == CustomUser.AdminAccountType.TRIAL):
        messages.error(request, "This action is only for Admins on a Trial account.")
        return redirect('accounts:admin_dashboard')
    if admin_user.trial_extension_requested:
        messages.info(request, "You have already submitted a trial extension request.")
        return redirect('accounts:admin_dashboard')
    if request.method == 'POST':
        form = AdminTrialExtensionRequestForm(request.POST)
        if form.is_valid():
            admin_user.trial_extension_requested = True
            admin_user.trial_extension_reason = form.cleaned_data['trial_extension_reason']
            admin_user.save(update_fields=['trial_extension_requested', 'trial_extension_reason'])
            messages.success(request, "Your trial extension request has been submitted.")
            send_trial_extension_request_to_superadmins_email(admin_user, request)
    return redirect('accounts:admin_dashboard')

@login_required
@admin_required
def admin_add_user_view(request):
    if request.user.role != CustomUser.ADMIN: 
        messages.error(request,"Only Admins can add users.")
        return redirect('accounts:dashboard')
    if not request.user.can_approve_more_users():
        messages.error(request, f"Cannot add new users: User limit reached or your account is inactive.")
        return redirect('accounts:admin_dashboard')
    if request.method=='POST':
        form = AdminAddUserForm(request.POST, prefix="add_new_user_by_admin_form")
        if form.is_valid(): 
            new_user=form.save(commit=True, added_by_admin=request.user, company_admin_instance=request.user)
            messages.success(request,f"User '{new_user.email}' created and approved."); 
            send_user_account_status_email(new_user, is_activated=True, by_who=request.user, request=request)
        else:
            for field, errors in form.errors.items(): 
                messages.error(request, f"Add User Error - {form.fields.get(field, type('obj', (object,), {'label': field})()).label}: {'; '.join(errors)}")
    return redirect('accounts:admin_dashboard')

@login_required
@admin_required
def approve_user_view(request, user_id):
    user_to_approve = get_object_or_404(CustomUser, pk=user_id, role=CustomUser.USER); approver = request.user
    is_authorized = (approver.role==CustomUser.SUPERADMIN) or (approver.role==CustomUser.ADMIN and user_to_approve.company_admin==approver)
    if not is_authorized: messages.error(request,"Not authorized to approve this user."); return redirect('accounts:admin_dashboard')
    if approver.role==CustomUser.ADMIN and not approver.can_approve_more_users():
        messages.error(request,f"Cannot approve {user_to_approve.email}: User limit reached or your account access is inactive.")
        return redirect('accounts:admin_dashboard')
    if user_to_approve.is_active and user_to_approve.approved_by: messages.warning(request, f"User {user_to_approve.email} is already active.")
    elif not user_to_approve.is_email_verified: messages.error(request, f"User {user_to_approve.email}'s email is not verified. Cannot approve.")
    else: 
        user_to_approve.is_active=True; user_to_approve.approved_by=approver
        user_to_approve.save(update_fields=['is_active','approved_by'])
        messages.success(request, f"User {user_to_approve.email} has been approved and activated.")
        send_user_account_status_email(user_to_approve, is_activated=True, by_who=approver, request=request)

    user_to_approve.is_active=True; user_to_approve.approved_by=approver
    user_to_approve.save(update_fields=['is_active','approved_by'])
    messages.success(request, f"User {user_to_approve.email} has been approved and activated.")
    send_user_account_status_email(user_to_approve, is_activated=True, by_who=approver, request=request)
    
    # --- ADD THE SAME START LOGIC HERE ---
    try:
        email_account = EmailAccount.objects.get(user=user_to_approve)
        email_account.is_active = True
        email_account.save(update_fields=['is_active'])
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.send)(
            "email-listener",
            {"type": "start.listening", "account_id": email_account.id}
        )
        logger.info(f"User {user_to_approve.email} approved, starting their email listener.")
    except EmailAccount.DoesNotExist:
        logger.info(f"User {user_to_approve.email} approved, but has no email config yet. Listener not started.")
    except Exception as e:
        logger.error(f"Failed to start email listener for {user_to_approve.email} on approval: {e}")

    return redirect('accounts:admin_dashboard')
    return redirect('accounts:admin_dashboard')

@login_required
@admin_required
def admin_manage_user_status_view(request, user_id, activate):
    """
    Activates or deactivates a user. This is the master switch.
    - On DEACTIVATION: It also stops the email monitoring listener and resets the
      user's email authentication status, requiring them to re-authenticate if
      they are ever reactivated.
    - On ACTIVATION: It simply marks the user as active. The email listener will
      only start if the user goes to the setup page and successfully authenticates.
    """
    target_user = get_object_or_404(CustomUser, pk=user_id, role=CustomUser.USER)
    manager = request.user
    
    # Authorization check: Superadmin can manage anyone. Admin can only manage their own users.
    is_authorized = (manager.is_superuser) or (manager.role == CustomUser.ADMIN and target_user.company_admin == manager)
    if not is_authorized:
        messages.error(request, "You are not authorized to manage this user.")
        return redirect('accounts:admin_dashboard')
    
    action_msg = ""
    original_is_active = target_user.is_active
    channel_layer = get_channel_layer()

    if activate:
        if original_is_active:
            messages.warning(request, f"User {target_user.email} is already active.")
        else:
            # Check if admin has capacity to activate a new user
            if manager.role == CustomUser.ADMIN and not manager.can_approve_more_users():
                messages.error(request, f"Cannot activate {target_user.email}: User limit reached or your account access is inactive.")
                return redirect('accounts:admin_dashboard')
            
            # Activate the user in the database
            target_user.is_active = True
            if not target_user.approved_by: target_user.approved_by = manager
            target_user.save(update_fields=['is_active', 'approved_by'] if not target_user.approved_by else ['is_active'])
            
            action_msg = "activated"
            send_user_account_status_email(target_user, is_activated=True, by_who=manager, request=request)
            
            # Note: We do NOT automatically start the listener here. The user must
            # re-authenticate their email credentials to start monitoring. This is a
            # security measure.

    else: # Deactivate
        if not original_is_active:
            messages.warning(request, f"User {target_user.email} is already inactive.")
        else:
            # Deactivate the user in the database
            target_user.is_active = False
            target_user.save(update_fields=['is_active'])
            
            action_msg = "deactivated"
            send_user_account_status_email(target_user, is_activated=False, by_who=manager, request=request)

            # --- UPDATED LOGIC: Also reset the email auth status and stop the listener ---
            try:
                email_account = EmailAccount.objects.get(user=target_user)
                
                # Check if there's anything to do to avoid unnecessary DB writes/signals
                if email_account.is_active or email_account.is_authenticated:
                    email_account.is_active = False
                    email_account.is_authenticated = False # <-- RESET THE AUTH FLAG
                    email_account.save(update_fields=['is_active', 'is_authenticated'])
                    
                    # Send the signal to the background worker to stop the task
                    async_to_sync(channel_layer.send)(
                        "email-listener",
                        {"type": "stop.listening", "account_id": email_account.id}
                    )
                    logger.info(f"Admin {manager.email} deactivated user {target_user.email}, stopping their email listener and resetting auth status.")
            except EmailAccount.DoesNotExist:
                # This is normal if the user never set up their email. Nothing to do.
                pass 
            except Exception as e:
                logger.error(f"Failed to stop email listener for {target_user.email} on deactivation: {e}")

    if action_msg:
        messages.success(request, f"User {target_user.email} has been successfully {action_msg}.")
    
    return redirect('accounts:admin_dashboard')

@login_required
def user_dashboard_view(request):
    """
    MODIFIED: A simple dashboard for the regular 'USER' role.
    This no longer contains any monitoring-specific logic.
    """
    user = request.user
    if user.role != CustomUser.USER:
        return redirect('accounts:dashboard')
    
    # In the template for this view, you can now link to the monitoring app dashboard
    # e.g., <a href="{% url 'monitor_app:dashboard' %}">View My Activity</a>
    context = { 'user': user }
    return render(request, 'accounts/user_dashboard.html', context)

# REMOVED: The admin_view_user_detail view has been removed.
# Its functionality is now handled by the views in the 'monitor_app'.


@login_required
@admin_required
def admin_view_user_detail(request, user_id):
    """
    Displays a detailed view for a single user by rendering a container
    template which in turn includes the live monitoring dashboard.
    """
    target_user = get_object_or_404(CustomUser, pk=user_id, role=CustomUser.USER)
    requesting_user = request.user

    # Authorization Check
    if not (requesting_user.role == 'SUPERADMIN' or target_user.company_admin == requesting_user):
        messages.error(request, "You are not authorized to view this user's details.")
        return redirect('accounts:admin_dashboard')

    # Prepare data for the embedded dashboard's JavaScript
    user_agents = Agent.objects.filter(user=target_user)
    agent_ids_json = json.dumps([agent.agent_id for agent in user_agents])

    context = {
        # 'title' is no longer needed here as the template sets it
        'target_user': target_user,
        'agent_ids_json': agent_ids_json,
        'is_single_user_view': True, # This is a CRITICAL flag for the included template
    }
    
    # This now renders your new 'shell' template
    return render(request, 'accounts/admin_user_detail.html', context)

@login_required
def user_download_agent_view(request):
    """
    Generates a new, short-lived pairing token for the logged-in user
    and displays it on a page with download instructions.
    """
    user = request.user

    # Ensure only employees (role='USER') can access this page
    if user.role != CustomUser.USER:
        messages.error(request, "Only employee accounts can be paired with an agent.")
        return redirect('accounts:dashboard') # Redirect admins/superadmins away

    # Generate a new token. The generate_agent_pairing_token() method
    # handles saving it to the user model.
    user.generate_agent_pairing_token()
    
    context = {
        'title': "Download & Pair Agent",
        'pairing_token': user.agent_pairing_token,
    }
    return render(request, 'accounts/download_agent.html', context)