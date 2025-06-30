# accounts/utils.py
import random
import logging
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.utils import timezone
import traceback 
from django.urls import reverse 
from django.template.loader import render_to_string 
# DO NOT import CustomUser from .models here at the top level

logger = logging.getLogger(__name__)

# ... (generate_otp, _send_email_with_logging - these don't directly need CustomUser type hint for params if used carefully) ...
def generate_otp(length=6):
    return str(random.randint(10**(length-1), (10**length) - 1))

def _send_email_with_logging(subject, plain_message, recipient_list, 
                             from_email=None, html_message=None, email_type="GENERIC", request=None):
    if not from_email:
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'webmaster@localhost')
    logger.info(f"{email_type}_EMAIL: Attempting to send to {recipient_list} from '{from_email}'. Subject: '{subject}'")
    try:
        if html_message:
            msg = EmailMultiAlternatives(subject, plain_message, from_email, recipient_list)
            msg.attach_alternative(html_message, "text/html")
            msg.send(fail_silently=False)
        else:
            send_mail(subject, plain_message, from_email, recipient_list, fail_silently=False)
        logger.info(f"{email_type}_EMAIL: Successfully sent to {recipient_list}.")
        return True
    except Exception as e:
        logger.error(f"{email_type}_EMAIL: FAILED to send to {recipient_list}. Error: {type(e).__name__} - {e}")
        logger.error(f"{email_type}_EMAIL: Full traceback:\n{traceback.format_exc()}")
        # Print to console as well for immediate debugging
        print(f"EMAIL ERROR: {type(e).__name__} - {e}")
        print(f"EMAIL ERROR TRACEBACK:\n{traceback.format_exc()}")
        return False

def send_registration_otp_email(user_instance, request=None):
    # user_instance is already a CustomUser object passed in
    # ... (rest of the function as before)
    otp = generate_otp()
    user_instance.email_otp = otp
    user_instance.otp_created_at = timezone.now()
    user_instance.save(update_fields=['email_otp', 'otp_created_at'])
    site_name = request.get_host() if request else getattr(settings, 'SITE_NAME', 'Our Platform')
    context = {'user': user_instance, 'otp': otp, 'site_name': site_name}
    subject = render_to_string('accounts/email/registration_otp_subject.txt', context).strip()
    plain_message = render_to_string('accounts/email/registration_otp_body.txt', context)
    return _send_email_with_logging(subject, plain_message, [user_instance.email], email_type="REG_OTP", request=request)


def send_password_reset_otp_email(user_instance, request=None):
    # ... (similar, user_instance is CustomUser)
    otp = generate_otp()
    user_instance.email_otp = otp
    user_instance.otp_created_at = timezone.now()
    user_instance.save(update_fields=['email_otp', 'otp_created_at'])
    site_name = request.get_host() if request else getattr(settings, 'SITE_NAME', 'Our Platform')
    context = {'user': user_instance, 'otp': otp, 'site_name': site_name}
    subject = render_to_string('accounts/email/password_reset_otp_subject.txt', context).strip()
    plain_message = render_to_string('accounts/email/password_reset_otp_body.txt', context)
    return _send_email_with_logging(subject, plain_message, [user_instance.email], email_type="PASS_RESET_OTP", request=request)


def send_user_account_status_email(user_instance, is_activated, by_who=None, reason=None, request=None):
    from .models import CustomUser # <--- Import inside function
    site_name = request.get_host() if request else getattr(settings, 'SITE_NAME', 'Our Platform')
    login_url = request.build_absolute_uri(reverse('accounts:login')) if request else f"https://{site_name}{reverse('accounts:login')}"
    approver_name = "System Administration"
    if by_who:
        if isinstance(by_who, CustomUser): approver_name = by_who.get_full_name()
        elif isinstance(by_who, str): approver_name = by_who
    context = {'user': user_instance, 'site_name': site_name, 'login_url': login_url, 'actor_name': approver_name, 'reason': reason}
    # ... (rest of function as before)
    if is_activated:
        subject_template = 'accounts/email/user_account_activated_subject.txt'; body_template = 'accounts/email/user_account_activated_body.txt'; email_type = "USER_ACTIVATED"; context['approver_name'] = approver_name
    else:
        subject_template = 'accounts/email/user_account_deactivated_subject.txt'; body_template = 'accounts/email/user_account_deactivated_body.txt'; email_type = "USER_DEACTIVATED"
    subject = render_to_string(subject_template, context).strip(); plain_message = render_to_string(body_template, context)
    return _send_email_with_logging(subject, plain_message, [user_instance.email], email_type=email_type, request=request)


def send_admin_access_status_email(admin_user, request=None, triggered_by_superadmin=None):
    from .models import CustomUser # <--- Import inside function
    site_name = request.get_host() if request else getattr(settings, 'SITE_NAME', 'Our Platform')
    login_url = request.build_absolute_uri(reverse('accounts:login')) if request else f"https://{site_name}{reverse('accounts:login')}"
    actor = "System Update"
    if triggered_by_superadmin and isinstance(triggered_by_superadmin, CustomUser): actor = triggered_by_superadmin.get_full_name()
    elif request and request.user.is_authenticated and isinstance(request.user, CustomUser) and request.user.role == CustomUser.SUPERADMIN: actor = request.user.get_full_name()
    context = {'admin_user': admin_user, 'site_name': site_name, 'login_url': login_url, 'actor_name': actor}
    # ... (rest of function as before, using admin_user.AdminAccountType which is fine)
    subject_template, body_template, email_type = None, None, None
    if admin_user.admin_account_type == CustomUser.AdminAccountType.TRIAL and admin_user.is_admin_access_active:
        subject_template = 'accounts/email/admin_trial_activated_subject.txt'; body_template = 'accounts/email/admin_trial_activated_body.txt'; email_type = "ADMIN_TRIAL_SET"
    elif admin_user.admin_account_type == CustomUser.AdminAccountType.SUBSCRIBED and admin_user.is_admin_access_active:
        subject_template = 'accounts/email/admin_subscription_activated_subject.txt'; body_template = 'accounts/email/admin_subscription_activated_body.txt'; email_type = "ADMIN_SUB_SET"
    elif admin_user.admin_account_type == CustomUser.AdminAccountType.EXPIRED or not admin_user.is_admin_access_active:
        subject_template = 'accounts/email/admin_access_expired_subject.txt'; body_template = 'accounts/email/admin_access_expired_body.txt'; email_type = "ADMIN_ACCESS_EXPIRED"
    else: logger.warning(f"send_admin_access_status_email: Unhandled state for admin {admin_user.email}."); return False
    subject = render_to_string(subject_template, context).strip(); plain_message = render_to_string(body_template, context)
    return _send_email_with_logging(subject, plain_message, [admin_user.email], email_type=email_type, request=request)


def send_admin_access_expiry_warning_email(admin_user, request=None):
    from .models import CustomUser # <--- Import inside function
    # ... (rest of function as before)
    if not (admin_user.role == CustomUser.ADMIN and admin_user.is_admin_access_active): return False
    days_remaining = admin_user.access_days_remaining
    if days_remaining is None or days_remaining < 0: return False 
    site_name = request.get_host() if request else getattr(settings, 'SITE_NAME', 'Our Platform')
    login_url = request.build_absolute_uri(reverse('accounts:login')) if request else f"https://{site_name}{reverse('accounts:login')}"
    context = {'admin_user': admin_user, 'days_remaining': days_remaining, 'site_name': site_name, 'login_url': login_url}
    subject = render_to_string('accounts/email/admin_access_expiry_warning_subject.txt', context).strip()
    plain_message = render_to_string('accounts/email/admin_access_expiry_warning_body.txt', context)
    return _send_email_with_logging(subject, plain_message, [admin_user.email], email_type="ADMIN_EXPIRY_WARN", request=request)

def _get_superadmin_emails():
    from .models import CustomUser # <--- Import inside function
    return list(CustomUser.objects.filter(role=CustomUser.SUPERADMIN, is_active=True, is_email_verified=True).values_list('email', flat=True))

def send_admin_registration_approval_request_email(admin_user_being_registered, request):
    # ... (as before, calls _get_superadmin_emails which now imports CustomUser internally)
    superadmin_emails = _get_superadmin_emails() # This will work now
    if not superadmin_emails: logger.warning(f"No Superadmins for Admin {admin_user_being_registered.email} approval."); return False
    context = {'admin_user': admin_user_being_registered, 'approval_link': request.build_absolute_uri(reverse('accounts:superadmin_dashboard')), 'site_name': request.get_host()}
    subject = render_to_string('accounts/email/admin_approval_request_subject.txt',context).strip()
    body = render_to_string('accounts/email/admin_approval_request_body.txt',context)
    return _send_email_with_logging(subject, body, superadmin_emails, email_type="ADMIN_APPROVAL_REQ", request=request)

def send_admin_approval_confirmation_email(approved_admin_user, request):
    # ... (as before, calls send_admin_access_status_email which imports CustomUser internally)
    site_name = request.get_host(); login_url = request.build_absolute_uri(reverse('accounts:login'))
    context = {'admin_user': approved_admin_user, 'login_url': login_url, 'site_name': site_name, 'actor_name': request.user.get_full_name()}
    subject = render_to_string('accounts/email/admin_account_activated_subject.txt',context).strip()
    body = render_to_string('accounts/email/admin_account_activated_body.txt',context)
    _send_email_with_logging(subject, body, [approved_admin_user.email], email_type="ADMIN_APPROVED_GENERIC", request=request)
    send_admin_access_status_email(approved_admin_user, request, triggered_by_superadmin=request.user)

def send_user_registration_approval_request_email(user_to_be_approved, company_admin, request):
    # ... (as before)
    if not company_admin or not company_admin.email: logger.warning(f"No Company Admin for user {user_to_be_approved.email}"); return False
    context = {'user_instance':user_to_be_approved, 'company_admin':company_admin, 'approval_link':request.build_absolute_uri(reverse('accounts:admin_dashboard')), 'site_name':request.get_host()}
    subject=render_to_string('accounts/email/user_approval_request_subject.txt',context).strip()
    body=render_to_string('accounts/email/user_approval_request_body.txt',context)
    return _send_email_with_logging(subject, body, [company_admin.email], email_type="USER_APPROVAL_REQ", request=request)

def send_user_approval_confirmation_email(approved_user, request):
    return send_user_account_status_email(approved_user, is_activated=True, by_who=request.user, request=request)

def send_trial_extension_request_to_superadmins_email(requesting_admin, request):
    # ... (as before, calls _get_superadmin_emails)
    superadmin_emails = _get_superadmin_emails()
    if not superadmin_emails: logger.warning(f"No Superadmins for trial ext req from {requesting_admin.email}."); return False
    context = {'requesting_admin_name':requesting_admin.get_full_name(), 'requesting_admin_email':requesting_admin.email, 'requesting_admin_trial_ends_at':requesting_admin.access_ends_at, 'extension_reason':requesting_admin.trial_extension_reason, 'superadmin_dashboard_url':request.build_absolute_uri(reverse('accounts:superadmin_dashboard')), 'site_name':request.get_host()}
    subject = render_to_string('accounts/email/admin_trial_extension_request_to_superadmin_subject.txt', context).strip()
    body = render_to_string('accounts/email/admin_trial_extension_request_to_superadmin_body.txt', context)
    return _send_email_with_logging(subject, body, superadmin_emails, email_type="TRIAL_EXT_REQ_TO_SA", request=request)

def send_admin_trial_extension_status_email(admin_user, status_is_approved, superadmin_actor, superadmin_message=None, request=None):
    from .models import CustomUser # <--- Import inside function
    # ... (rest of function as before)
    site_name = request.get_host() if request else getattr(settings, 'SITE_NAME', 'Our Platform')
    login_url = request.build_absolute_uri(reverse('accounts:login')) if request else f"https://{site_name}{reverse('accounts:login')}"
    context = {'admin_user': admin_user, 'status': "Approved" if status_is_approved else "Not Approved", 'new_trial_ends_at': admin_user.access_ends_at if status_is_approved and admin_user.admin_account_type == CustomUser.AdminAccountType.TRIAL else None, 'superadmin_message': superadmin_message, 'site_name': site_name, 'login_url': login_url, 'actor_name': superadmin_actor.get_full_name() if superadmin_actor else "Superadmin"}
    subject = render_to_string('accounts/email/admin_trial_extension_status_subject.txt', context).strip()
    body = render_to_string('accounts/email/admin_trial_extension_status_body.txt', context)
    return _send_email_with_logging(subject, body, [admin_user.email], email_type="TRIAL_EXT_STATUS", request=request)