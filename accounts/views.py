# accounts/views.py
import json
import traceback
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib import messages
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
    AdminTrialExtensionRequestForm, SuperadminTrialExtensionForm,
    AgentMonitoringConfigForm, AdminFeatureRestrictionsForm
)
from .models import CustomUser, AdminFeatureRestrictions
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
from .decorators import otp_session_required, superadmin_required, admin_required, user_required
from monitor_app.models import Agent

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from mail_monitor.models import EmailAccount, CompanyEmailConfig
from .models import CompanyBreakSchedule, UserBreakSchedule

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
            if not user.email_otp:
                messages.error(request, 'No OTP found. Please request a new one.')
                return redirect('accounts:verify_otp')
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

            # Clear other sessions for this user
            try:
                from django.contrib.sessions.models import Session
                current_session_key = request.session.session_key 
                for session_obj in Session.objects.filter(expire_date__gte=timezone.now()):
                    session_data = session_obj.get_decoded()
                    if session_data.get('_auth_user_id') == str(user_to_login.pk) and session_obj.session_key != current_session_key:
                        session_obj.delete()
            except Exception as e:
                logger.warning(f"Error clearing sessions for user {user_to_login.email}: {e}")

            auth_login(request, user_to_login)
            messages.success(request, f'Welcome back, {user_to_login.get_full_name()}!')
            return redirect(settings.LOGIN_REDIRECT_URL)
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
        # Get or create feature restrictions for this admin
        restrictions = AdminFeatureRestrictions.get_or_create_for_admin(admin)

        admin_details_list.append({
            'user': admin,
            'current_users': admin.get_current_approved_users_count(),
            'access_form': SuperadminManageAdminAccessForm(instance=admin, prefix=f"access_form_{admin.pk}"),
            'restrictions_form': AdminFeatureRestrictionsForm(instance=restrictions, prefix=f"restrictions_form_{admin.pk}"),
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
        # Get feature restrictions for this admin
        feature_restrictions = AdminFeatureRestrictions.get_or_create_for_admin(viewer)

        context.update({
            'is_admin_role_view': True,
            'admin_user_instance': viewer,
            'feature_restrictions': feature_restrictions,
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

    # --- START EMAIL LISTENER IF EMAIL ACCOUNT EXISTS ---
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
            # Deactivate the user and stop all their agents
            _deactivate_user_and_agents(target_user, manager)

            action_msg = "deactivated"
            send_user_account_status_email(target_user, is_activated=False, by_who=manager, request=request)

    if action_msg:
        messages.success(request, f"User {target_user.email} has been successfully {action_msg}.")

    return redirect('accounts:admin_dashboard')


def _deactivate_user_and_agents(user, deactivated_by):
    """
    Helper function to deactivate a user and stop all their monitoring agents.
    This includes stopping email listeners and disabling agent monitoring.
    """
    from monitor_app.models import Agent
    from mail_monitor.models import EmailAccount

    user.is_active = False
    user.save(update_fields=['is_active'])

    channel_layer = get_channel_layer()

    # Stop all monitoring agents for this user
    user_agents = Agent.objects.filter(user=user)
    for agent in user_agents:
        # Disable the agent (you could also delete it if preferred)
        agent.is_activity_monitoring_enabled = False
        agent.is_network_monitoring_enabled = False
        agent.is_live_streaming_enabled = False
        agent.save(update_fields=[
            'is_activity_monitoring_enabled', 
            'is_network_monitoring_enabled', 
            'is_live_streaming_enabled'
        ])
        logger.info(f"Disabled monitoring for agent {agent.agent_id} belonging to user {user.email}")

    # Stop email monitoring
    try:
        email_account = EmailAccount.objects.get(user=user)

        if email_account.is_active or email_account.is_authenticated:
            email_account.is_active = False
            email_account.is_authenticated = False
            email_account.save(update_fields=['is_active', 'is_authenticated'])

            # Send the signal to the background worker to stop the task
            async_to_sync(channel_layer.send)(
                "email-listener",
                {"type": "stop.listening", "account_id": email_account.id}
            )
            logger.info(f"User {user.email} deactivated, stopping their email listener and resetting auth status.")
    except EmailAccount.DoesNotExist:
        pass 
    except Exception as e:
        logger.error(f"Failed to stop email listener for {user.email} on deactivation: {e}")


def _deactivate_admin_and_cascade(admin_user, deactivated_by):
    """
    Helper function to deactivate an admin and cascade the deactivation to all their employees.
    This stops all monitoring for the admin's company.
    """
    from monitor_app.models import Agent
    from mail_monitor.models import EmailAccount, CompanyEmailConfig

    # Deactivate the admin
    admin_user.is_active = False
    admin_user.max_allowed_users = 0
    admin_user.admin_account_type = CustomUser.AdminAccountType.EXPIRED
    admin_user.save(update_fields=['is_active', 'max_allowed_users', 'admin_account_type'])

    # Get all employees under this admin
    employees = CustomUser.objects.filter(company_admin=admin_user, role=CustomUser.USER)

    channel_layer = get_channel_layer()

    # Emergency stop all agents for this company immediately
    company_agents = Agent.objects.filter(user__company_admin=admin_user)
    for agent in company_agents:
        # Send emergency stop command to all active agents
        emergency_stop_message = {
            "type": "emergency_stop",
            "reason": f"Admin {admin_user.email} has been deactivated",
            "action": "disable_all_monitoring"
        }
        async_to_sync(channel_layer.group_send)(
            f"agent_{agent.agent_id}",
            {
                "type": "control_command",
                "command": emergency_stop_message
            }
        )

        # Disable all monitoring features in database
        agent.is_activity_monitoring_enabled = False
        agent.is_network_monitoring_enabled = False
        agent.is_live_streaming_enabled = False
        agent.is_video_recording_enabled = False
        agent.is_keystroke_logging_enabled = False
        agent.is_email_monitoring_enabled = False
        agent.save()

    # Deactivate all employees and their agents
    for employee in employees:
        if employee.is_active:
            _deactivate_user_and_agents(employee, deactivated_by)
            send_user_account_status_email(
                employee, 
                is_activated=False, 
                by_who=deactivated_by, 
                reason=f"Company admin {admin_user.email} has been deactivated"
            )

    # Disable company email monitoring configuration
    try:
        company_config = CompanyEmailConfig.objects.get(admin=admin_user)
        company_config.is_monitoring_enabled = False
        company_config.save(update_fields=['is_monitoring_enabled'])
        logger.info(f"Disabled company email monitoring for admin {admin_user.email}")
    except CompanyEmailConfig.DoesNotExist:
        pass
    except Exception as e:
        logger.error(f"Failed to disable company email monitoring for admin {admin_user.email}: {e}")

    logger.info(f"Admin {admin_user.email} and all their employees have been deactivated by {deactivated_by.email}")


@login_required
@superadmin_required
def superadmin_deactivate_admin_view(request, admin_id):
    """
    New view to allow superadmins to completely deactivate an admin and all their employees.
    This is a comprehensive shutdown of the admin's company operations.
    """
    admin_user = get_object_or_404(CustomUser, pk=admin_id, role=CustomUser.ADMIN)

    if not admin_user.is_active:
        messages.warning(request, f"Admin {admin_user.email} is already inactive.")
        return redirect('accounts:superadmin_dashboard')

    # Get count of employees that will be affected
    employee_count = CustomUser.objects.filter(company_admin=admin_user, role=CustomUser.USER, is_active=True).count()

    # Perform the cascading deactivation
    _deactivate_admin_and_cascade(admin_user, request.user)

    # Send notification to the admin
    send_user_account_status_email(
        admin_user, 
        is_activated=False, 
        by_who=request.user, 
        reason="Account deactivated by superadmin - all monitoring privileges withdrawn"
    )

    messages.success(
        request, 
        f"Admin {admin_user.email} has been completely deactivated. {employee_count} employees were also deactivated and all monitoring agents stopped."
    )

    return redirect('accounts:superadmin_dashboard')


@login_required
@superadmin_required
def superadmin_activate_admin_view(request, admin_id):
    """
    View to allow superadmins to reactivate a deactivated admin.
    Sets them to trial with default settings.
    """
    admin_user = get_object_or_404(CustomUser, pk=admin_id, role=CustomUser.ADMIN)

    if admin_user.is_active and admin_user.is_admin_access_active:
        messages.warning(request, f"Admin {admin_user.email} is already active.")
        return redirect('accounts:superadmin_dashboard')

    # Reactivate the admin with trial settings
    admin_user.is_active = True
    admin_user.admin_account_type = CustomUser.AdminAccountType.TRIAL
    default_trial_days = getattr(settings, 'DEFAULT_ADMIN_TRIAL_DAYS', 7)
    admin_user.access_ends_at = timezone.now() + timedelta(days=default_trial_days)
    admin_user.max_allowed_users = 5  # Default user limit
    admin_user.access_granted_by = request.user
    admin_user.trial_extension_requested = False
    admin_user.trial_extension_reason = None
    admin_user.save()

    # Send notification to the admin
    send_admin_access_status_email(admin_user, request, triggered_by_superadmin=request.user)

    messages.success(
        request, 
        f"Admin {admin_user.email} has been reactivated with a {default_trial_days}-day trial period and 5 user limit."
    )

    return redirect('accounts:superadmin_dashboard')


@login_required
@superadmin_required
def superadmin_extend_trial_view(request, admin_id):
    """
    View to allow superadmins to extend an admin's trial period by adding days.
    """
    admin_user = get_object_or_404(CustomUser, pk=admin_id, role=CustomUser.ADMIN)

    if admin_user.admin_account_type != CustomUser.AdminAccountType.TRIAL:
        messages.error(request, f"Admin {admin_user.email} is not on a trial account. Cannot extend trial.")
        return redirect('accounts:superadmin_dashboard')

    if request.method == 'POST':
        from .forms import SuperadminTrialExtensionForm
        form = SuperadminTrialExtensionForm(request.POST)
        if form.is_valid():
            extension_days = form.cleaned_data['extension_days']

            # Calculate new end date by adding days to current end date
            if admin_user.access_ends_at:
                # If trial hasn't expired yet, add to existing end date
                if admin_user.access_ends_at > timezone.now():
                    new_end_date = admin_user.access_ends_at + timedelta(days=extension_days)
                else:
                    # If trial has expired, add to current time
                    new_end_date = timezone.now() + timedelta(days=extension_days)
            else:
                # No end date set, start from now
                new_end_date = timezone.now() + timedelta(days=extension_days)

            admin_user.access_ends_at = new_end_date
            admin_user.access_granted_by = request.user
            admin_user.trial_extension_requested = False
            admin_user.trial_extension_reason = None
            admin_user.save()

            # Send notification to the admin
            send_admin_access_status_email(admin_user, request, triggered_by_superadmin=request.user)

            messages.success(
                request, 
                f"Extended trial for {admin_user.email} by {extension_days} days. New end date: {new_end_date.strftime('%B %d, %Y')}"
            )
        else:
            messages.error(request, "Invalid extension days. Please enter a value between 1 and 365.")

    return redirect('accounts:superadmin_dashboard')


@login_required
@superadmin_required
def superadmin_manage_feature_restrictions_view(request, admin_id):
    """
    View to allow superadmins to manage feature restrictions for admin companies.
    This controls what monitoring features are available based on subscription level.
    """
    admin_user = get_object_or_404(CustomUser, pk=admin_id, role=CustomUser.ADMIN)
    restrictions = AdminFeatureRestrictions.get_or_create_for_admin(admin_user)

    form_prefix = f"restrictions_form_{admin_user.pk}"

    if request.method == 'POST':
        form = AdminFeatureRestrictionsForm(request.POST, instance=restrictions, prefix=form_prefix)
        if form.is_valid():
            form.save()
            messages.success(
                request, 
                f"Feature restrictions updated for {admin_user.email}. These changes will take effect immediately."
            )

            # If certain premium features are disabled, we should also disable them on existing agents
            _update_existing_agents_based_on_restrictions(admin_user, restrictions)

        else:
            for field, errors in form.errors.items():
                messages.error(request, f"Feature Restrictions Error ({admin_user.email}) - {field}: {'; '.join(errors)}")

    return redirect('accounts:superadmin_dashboard')


def _update_existing_agents_based_on_restrictions(admin_user, restrictions):
    """
    Helper function to update existing agents when feature restrictions change.
    This ensures that if a feature is disabled, existing agents lose access immediately.
    """
    try:
        from monitor_app.models import Agent

        # Get all agents for users under this admin
        affected_agents = Agent.objects.filter(user__company_admin=admin_user)

        update_fields = []
        updates = {}

        # Disable features that are no longer allowed
        if not restrictions.can_use_activity_monitoring:
            updates['is_activity_monitoring_enabled'] = False
            update_fields.append('is_activity_monitoring_enabled')

        if not restrictions.can_use_network_monitoring:
            updates['is_network_monitoring_enabled'] = False
            update_fields.append('is_network_monitoring_enabled')


        if not restrictions.can_use_live_streaming:
            updates['is_live_streaming_enabled'] = False
            update_fields.append('is_live_streaming_enabled')

        if not restrictions.can_use_video_recording:
            updates['is_video_recording_enabled'] = False
            update_fields.append('is_video_recording_enabled')

        if not restrictions.can_use_keystroke_logging:
            updates['is_keystroke_logging_enabled'] = False
            update_fields.append('is_keystroke_logging_enabled')

        if not restrictions.can_use_email_monitoring:
            updates['is_email_monitoring_enabled'] = False
            update_fields.append('is_email_monitoring_enabled')

        if updates:
            affected_agents.update(**updates)
            logger.info(f"Updated {affected_agents.count()} agents for admin {admin_user.email} based on new feature restrictions")

    except Exception as e:
        logger.error(f"Failed to update agents for admin {admin_user.email} after restriction changes: {e}")


@login_required
@admin_required
def admin_configure_monitoring_view(request, user_id):
    """
    Allow admin to configure monitoring settings for a specific user's agents.
    Now respects feature restrictions based on admin's subscription level.
    """
    target_user = get_object_or_404(CustomUser, pk=user_id, role=CustomUser.USER)
    requesting_admin = request.user

    # Authorization check
    if not (requesting_admin.role == CustomUser.SUPERADMIN or target_user.company_admin == requesting_admin):
        messages.error(request, "You are not authorized to configure monitoring for this user.")
        return redirect('accounts:admin_dashboard')

    # Check if admin has permission to configure monitoring
    if requesting_admin.role == CustomUser.ADMIN:
        feature_restrictions = AdminFeatureRestrictions.get_or_create_for_admin(requesting_admin)
        if not feature_restrictions.can_configure_monitoring:
            messages.error(request, "Monitoring configuration is not available on your current subscription plan.")
            return redirect('accounts:admin_dashboard')
    else:
        # Superadmin has no restrictions
        feature_restrictions = None

    if request.method == 'POST':
        form = AgentMonitoringConfigForm(request.POST)
        if form.is_valid():
            # Update all agents for this user, but respect feature restrictions
            from monitor_app.models import Agent
            user_agents = Agent.objects.filter(user=target_user)

            if user_agents.exists():
                update_fields = {}

                # Apply restrictions if this is an admin (not superadmin)
                if feature_restrictions:
                    update_fields['is_activity_monitoring_enabled'] = (
                        form.cleaned_data['is_activity_monitoring_enabled'] and 
                        feature_restrictions.can_use_activity_monitoring
                    )
                    update_fields['is_network_monitoring_enabled'] = (
                        form.cleaned_data['is_network_monitoring_enabled'] and 
                        feature_restrictions.can_use_network_monitoring
                    )

                    update_fields['is_live_streaming_enabled'] = (
                        form.cleaned_data['is_live_streaming_enabled'] and 
                        feature_restrictions.can_use_live_streaming
                    )
                    update_fields['is_video_recording_enabled'] = (
                        form.cleaned_data['is_video_recording_enabled'] and 
                        feature_restrictions.can_use_video_recording
                    )
                    update_fields['is_keystroke_logging_enabled'] = (
                        form.cleaned_data['is_keystroke_logging_enabled'] and 
                        feature_restrictions.can_use_keystroke_logging
                    )
                    update_fields['is_email_monitoring_enabled'] = (
                        form.cleaned_data['is_email_monitoring_enabled'] and 
                        feature_restrictions.can_use_email_monitoring
                    )
                else:
                    # Superadmin has no restrictions
                    update_fields = {
                        'is_activity_monitoring_enabled': form.cleaned_data['is_activity_monitoring_enabled'],
                        'is_network_monitoring_enabled': form.cleaned_data['is_network_monitoring_enabled'],
                        'is_live_streaming_enabled': form.cleaned_data['is_live_streaming_enabled'],
                        'is_video_recording_enabled': form.cleaned_data['is_video_recording_enabled'],
                        'is_keystroke_logging_enabled': form.cleaned_data['is_keystroke_logging_enabled'],
                        'is_email_monitoring_enabled': form.cleaned_data['is_email_monitoring_enabled'],
                    }

                update_fields['capture_interval_seconds'] = form.cleaned_data['capture_interval_seconds']

                user_agents.update(**update_fields)
                messages.success(request, f"Monitoring configuration updated for {target_user.email} ({user_agents.count()} agents affected)")

                # Inform admin if some features were automatically disabled due to restrictions
                if feature_restrictions:
                    disabled_features = []
                    if form.cleaned_data['is_live_streaming_enabled'] and not feature_restrictions.can_use_live_streaming:
                        disabled_features.append("Live Streaming")
                    if form.cleaned_data['is_video_recording_enabled'] and not feature_restrictions.can_use_video_recording:
                        disabled_features.append("Video Recording")
                    if form.cleaned_data['is_keystroke_logging_enabled'] and not feature_restrictions.can_use_keystroke_logging:
                        disabled_features.append("Keystroke Logging")
                    if form.cleaned_data['is_email_monitoring_enabled'] and not feature_restrictions.can_use_email_monitoring:
                        disabled_features.append("Email Monitoring")

                    if disabled_features:
                        messages.warning(request, f"Note: {', '.join(disabled_features)} were not enabled due to subscription restrictions.")
            else:
                messages.info(request, f"No agents found for {target_user.email}. Settings will apply when agent is connected.")

            return redirect('accounts:admin_dashboard')
    else:
        # Get current settings from user's first agent, or use defaults
        from monitor_app.models import Agent
        first_agent = Agent.objects.filter(user=target_user).first()

        if first_agent:
            initial_data = {
                'is_activity_monitoring_enabled': first_agent.is_activity_monitoring_enabled,
                'is_network_monitoring_enabled': first_agent.is_network_monitoring_enabled,
                'is_live_streaming_enabled': first_agent.is_live_streaming_enabled,
                'is_video_recording_enabled': getattr(first_agent, 'is_video_recording_enabled', False),
                'is_keystroke_logging_enabled': getattr(first_agent, 'is_keystroke_logging_enabled', False),
                'is_email_monitoring_enabled': getattr(first_agent, 'is_email_monitoring_enabled', False),
                'capture_interval_seconds': first_agent.capture_interval_seconds,
            }
            form = AgentMonitoringConfigForm(initial=initial_data)
        else:
            form = AgentMonitoringConfigForm()

    context = {
        'form': form,
        'target_user': target_user,
        'feature_restrictions': feature_restrictions,
        'title': f'Configure Monitoring for {target_user.get_full_name()}'
    }

    return render(request, 'accounts/configure_monitoring.html', context)


@login_required
@admin_required
def manage_break_schedules_view(request):
    """
    Manage company-wide and user-specific break schedules.
    """
    from .forms import CompanyBreakScheduleForm, UserBreakScheduleForm
    from .models import CompanyBreakSchedule, UserBreakSchedule

    # Get all company break schedules for this admin
    company_schedules = CompanyBreakSchedule.objects.filter(
        admin=request.user
    ).order_by('day', 'start_time')

    # Get all user break schedules for this admin's users
    managed_users = CustomUser.objects.filter(
        company_admin=request.user, 
        role=CustomUser.USER
    )
    users_with_breaks = UserBreakSchedule.objects.filter(
        user__in=managed_users
    ).select_related('user').order_by('user__email', 'day', 'start_time')

    if request.method == 'POST':
        form_type = request.POST.get('form_type')

        if form_type == 'company':
            company_form = CompanyBreakScheduleForm(request.POST)
            if company_form.is_valid():
                break_schedule = company_form.save(commit=False)
                break_schedule.admin = request.user
                break_schedule.save()

                # Notify all agents to refresh their configuration
                from channels.layers import get_channel_layer
                from asgiref.sync import async_to_sync

                channel_layer = get_channel_layer()
                for user in managed_users:
                    for agent in user.agents.all():
                        async_to_sync(channel_layer.group_send)(
                            f"agent_{agent.agent_id}",
                            {
                                "type": "control_command",
                                "command": {
                                    "type": "control",
                                    "action": "refresh_config"
                                }
                            }
                        )

                messages.success(request, 'Company break schedule added successfully. Agents have been notified.')
                return redirect('accounts:manage_break_schedules')

        elif form_type == 'user':
            user_form = UserBreakScheduleForm(request.POST, admin=request.user)
            if user_form.is_valid():
                user_form.save()
                messages.success(request, 'User break schedule added successfully.')
                return redirect('accounts:manage_break_schedules')

        elif form_type == 'edit_user':
            break_id = request.POST.get('break_id')
            try:
                user_break = UserBreakSchedule.objects.get(
                    id=break_id, 
                    user__company_admin=request.user
                )
                user_form = UserBreakScheduleForm(request.POST, instance=user_break, admin=request.user)
                if user_form.is_valid():
                    user_form.save()
                    messages.success(request, 'User break schedule updated successfully.')
                    return redirect('accounts:manage_break_schedules')
            except UserBreakSchedule.DoesNotExist:
                messages.error(request, 'Break schedule not found.')

    company_form = CompanyBreakScheduleForm()
    user_form = UserBreakScheduleForm(admin=request.user)

    # Generate JWT token for API access
    access_token = None
    try:
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(request.user)
        access_token = str(refresh.access_token)
    except Exception as e:
        print(f"Could not generate access token for user {request.user.email}: {e}")

    context = {
        'company_form': company_form,
        'user_form': user_form,
        'users_with_breaks': users_with_breaks,
        'company_schedules': company_schedules,
        'managed_users': managed_users,
        'access_token': access_token,
    }

    return render(request, 'accounts/manage_break_schedules.html', context)

@login_required
@admin_required
def delete_user_break_view(request, break_id):
    """
    Delete a user-specific break schedule.
    """
    from .models import UserBreakSchedule
    try:
        user_break = UserBreakSchedule.objects.get(
            id=break_id, 
            user__company_admin=request.user
        )
        user_name = user_break.user.get_full_name()
        user_break.delete()
        messages.success(request, f'Break schedule for {user_name} deleted successfully.')
    except UserBreakSchedule.DoesNotExist:
        messages.error(request, 'Break schedule not found.')

    return redirect('accounts:manage_break_schedules')

@login_required
@admin_required
def bulk_configure_monitoring_view(request):
    """
    Allow admin to configure monitoring settings for ALL users under their company at once.
    """
    requesting_admin = request.user

    if requesting_admin.role != CustomUser.ADMIN:
        messages.error(request, "Only admins can access bulk configuration.")
        return redirect('accounts:admin_dashboard')

    # Check if admin has permission to configure monitoring
    feature_restrictions = AdminFeatureRestrictions.get_or_create_for_admin(requesting_admin)
    if not feature_restrictions.can_configure_monitoring:
        messages.error(request, "Monitoring configuration is not available on your current subscription plan.")
        return redirect('accounts:admin_dashboard')

    # Get all users under this admin
    company_users = CustomUser.objects.filter(company_admin=requesting_admin, role=CustomUser.USER)

    if request.method == 'POST':
        form = AgentMonitoringConfigForm(request.POST)
        if form.is_valid():
            # Update all agents for all users under this admin
            from monitor_app.models import Agent

            update_fields = {}

            # Apply restrictions based on admin's subscription
            update_fields['is_activity_monitoring_enabled'] = (
                form.cleaned_data['is_activity_monitoring_enabled'] and 
                feature_restrictions.can_use_activity_monitoring
            )
            update_fields['is_network_monitoring_enabled'] = (
                form.cleaned_data['is_network_monitoring_enabled'] and 
                feature_restrictions.can_use_network_monitoring
            )
            update_fields['is_screenshot_capturing_enabled'] = (
                form.cleaned_data['is_screenshot_capturing_enabled'] and 
                feature_restrictions.can_use_screenshot_capturing
            )
            update_fields['is_live_streaming_enabled'] = (
                form.cleaned_data['is_live_streaming_enabled'] and 
                feature_restrictions.can_use_live_streaming
            )
            update_fields['is_video_recording_enabled'] = (
                form.cleaned_data['is_video_recording_enabled'] and 
                feature_restrictions.can_use_video_recording
            )
            update_fields['is_keystroke_logging_enabled'] = (
                form.cleaned_data['is_keystroke_logging_enabled'] and 
                feature_restrictions.can_use_keystroke_logging
            )
            update_fields['is_email_monitoring_enabled'] = (
                form.cleaned_data['is_email_monitoring_enabled'] and 
                feature_restrictions.can_use_email_monitoring
            )
            update_fields['capture_interval_seconds'] = form.cleaned_data['capture_interval_seconds']

            # Apply to all agents of all users under this admin
            all_company_agents = Agent.objects.filter(user__in=company_users)
            updated_count = all_company_agents.update(**update_fields)

            messages.success(request, f"Monitoring configuration applied to all company users ({updated_count} agents affected)")

            # Inform admin if some features were automatically disabled due to restrictions
            disabled_features = []
            if form.cleaned_data['is_live_streaming_enabled'] and not feature_restrictions.can_use_live_streaming:
                disabled_features.append("Live Streaming")
            if form.cleaned_data['is_video_recording_enabled'] and not feature_restrictions.can_use_video_recording:
                disabled_features.append("Video Recording")
            if form.cleaned_data['is_keystroke_logging_enabled'] and not feature_restrictions.can_use_keystroke_logging:
                disabled_features.append("Keystroke Logging")
            if form.cleaned_data['is_email_monitoring_enabled'] and not feature_restrictions.can_use_email_monitoring:
                disabled_features.append("Email Monitoring")

            if disabled_features:
                messages.warning(request, f"Note: {', '.join(disabled_features)} were not enabled due to subscription restrictions.")

            return redirect('accounts:admin_dashboard')
    else:
        # Use default form values
        form = AgentMonitoringConfigForm()

    context = {
        'form': form,
        'feature_restrictions': feature_restrictions,
        'company_users': company_users,
        'title': 'Bulk Configure Monitoring for All Company Users'
    }

    return render(request, 'accounts/bulk_configure_monitoring.html', context)

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


@login_required
@admin_required
def break_overview_view(request):
    """
    Overview of all break schedules and current status.
    """
    from .models import UserBreakSchedule

    # Get all managed users
    managed_users = CustomUser.objects.filter(
        company_admin=request.user, 
        role=CustomUser.USER
    )

    # Get users currently on break
    current_time = timezone.now().time()
    current_day = timezone.now().strftime('%A').lower()

    users_on_break = UserBreakSchedule.objects.filter(
        user__in=managed_users,
        is_active=True,
        day=current_day,
        start_time__lte=current_time,
        end_time__gte=current_time
    ).exclude(is_on_leave=True)

    # Get users on leave
    users_on_leave = UserBreakSchedule.objects.filter(
        user__in=managed_users,
        is_active=True,
        is_on_leave=True
    )

    # Calculate users currently working
    users_on_break_ids = list(users_on_break.values_list('user_id', flat=True))
    users_on_leave_ids = list(users_on_leave.values_list('user_id', flat=True))
    excluded_user_ids = set(users_on_break_ids + users_on_leave_ids)
    users_working_count = managed_users.exclude(id__in=excluded_user_ids).count()

    context = {
        'total_managed_users': managed_users.count(),
        'users_on_break': users_on_break,
        'users_on_leave': users_on_leave,
        'users_working_count': users_working_count,
        'all_users': managed_users,
    }

    return render(request, 'accounts/break_overview.html', context)

@login_required
@admin_required
def bulk_break_management_view(request):
    """
    Bulk operations for break schedules - apply breaks to multiple users at once.
    """
    from .forms import BulkBreakScheduleForm
    from .models import UserBreakSchedule

    managed_users = CustomUser.objects.filter(
        company_admin=request.user, 
        role=CustomUser.USER,
        is_active=True
    )

    if request.method == 'POST':
        form = BulkBreakScheduleForm(request.POST, admin=request.user)
        if form.is_valid():
            selected_users = form.cleaned_data['users']
            operation = form.cleaned_data['operation']

            if operation == 'add_break':
                # Add break schedule to selected users
                for user in selected_users:
                    UserBreakSchedule.objects.create(
                        user=user,
                        name=form.cleaned_data['name'],
                        day=form.cleaned_data['day'],
                        start_time=form.cleaned_data['start_time'],
                        end_time=form.cleaned_data['end_time'],
                        is_active=True
                    )
                messages.success(request, f'Break schedule added to {selected_users.count()} users.')

            elif operation == 'set_leave':
                # Set leave status for selected users
                for user in selected_users:
                    UserBreakSchedule.objects.create(
                        user=user,
                        name=form.cleaned_data['leave_name'] or 'Leave',
                        is_on_leave=True,
                        leave_start_date=form.cleaned_data['leave_start_date'],
                        leave_end_date=form.cleaned_data['leave_end_date'],
                        leave_reason=form.cleaned_data['leave_reason'],
                        is_active=True
                    )
                messages.success(request, f'Leave status set for {selected_users.count()} users.')

            return redirect('accounts:bulk_break_management')
    else:
        form = BulkBreakScheduleForm(admin=request.user)

    context = {
        'form': form,
        'managed_users': managed_users,
    }

    return render(request, 'accounts/bulk_break_management.html', context)




@login_required
@admin_required
def edit_company_break_view(request, break_id):
    """
    Edit a company-wide break schedule.
    """
    from .forms import CompanyBreakScheduleForm
    from .models import CompanyBreakSchedule

    break_schedule = get_object_or_404(
        CompanyBreakSchedule, 
        id=break_id, 
        admin=request.user
    )

    if request.method == 'POST':
        form = CompanyBreakScheduleForm(request.POST, instance=break_schedule)
        if form.is_valid():
            form.save()
            messages.success(request, f'Company break schedule "{break_schedule.name}" updated successfully.')
            return redirect('accounts:break_overview')
    else:
        form = CompanyBreakScheduleForm(instance=break_schedule)

    context = {
        'form': form,
        'break_schedule': break_schedule,
        'title': f'Edit Company Break: {break_schedule.name}'
    }
    return render(request, 'accounts/edit_company_break.html', context)

@login_required
@admin_required
def delete_company_break_view(request, break_id):
    """
    Delete a company-wide break schedule.
    """
    from .models import CompanyBreakSchedule

    break_schedule = get_object_or_404(
        CompanyBreakSchedule, 
        id=break_id, 
        admin=request.user
    )

    break_name = break_schedule.name
    break_schedule.delete()
    messages.success(request, f'Company break schedule "{break_name}" deleted successfully.')
    return redirect('accounts:break_overview')

@login_required
@admin_required
def edit_user_break_view(request, break_id):
    """
    Edit a user-specific break schedule.
    """
    from .forms import UserBreakScheduleForm
    from .models import UserBreakSchedule

    break_schedule = get_object_or_404(
        UserBreakSchedule, 
        id=break_id, 
        user__company_admin=request.user
    )

    if request.method == 'POST':
        form = UserBreakScheduleForm(request.POST, instance=break_schedule, admin=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, f'User break schedule for {break_schedule.user.get_full_name()} updated successfully.')
            return redirect('accounts:break_overview')
    else:
        form = UserBreakScheduleForm(instance=break_schedule, admin=request.user)

    context = {
        'form': form,
        'break_schedule': break_schedule,
        'title': f'Edit Break for {break_schedule.user.get_full_name()}'
    }
    return render(request, 'accounts/edit_user_break.html', context)