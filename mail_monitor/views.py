# mail_monitor/views.py

import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import logging

# Import your custom models and decorators
from accounts.models import CustomUser
from accounts.decorators import admin_required, user_required

# Import from this app
from .forms import CompanyEmailConfigForm, UserAppPasswordForm
from .models import CompanyEmailConfig, EmailAccount, MonitoredEmail
from .utils import validate_imap_credentials

logger = logging.getLogger(__name__)

# This dictionary provides helpful presets for the admin's configuration form.
EMAIL_PROVIDER_PRESETS = {
    # Top Tier
    'gmail': {'name': 'Google / Gmail', 'imap_server': 'imap.gmail.com', 'smtp_server': 'smtp.gmail.com'},
    'outlook': {'name': 'Microsoft (Outlook, Hotmail, Live)', 'imap_server': 'outlook.office365.com', 'smtp_server': 'smtp.office365.com'},
    'yahoo': {'name': 'Yahoo Mail', 'imap_server': 'imap.mail.yahoo.com', 'smtp_server': 'smtp.mail.yahoo.com'},
    'icloud': {'name': 'Apple iCloud', 'imap_server': 'imap.mail.me.com', 'smtp_server': 'smtp.mail.me.com', 'smtp_port': 587},
    'aol': {'name': 'AOL Mail', 'imap_server': 'imap.aol.com', 'smtp_server': 'smtp.aol.com', 'smtp_port': 587},
    
    # Major International Providers
    'gmx': {'name': 'GMX', 'imap_server': 'imap.gmx.com', 'smtp_server': 'mail.gmx.com', 'smtp_port': 587},
    'zoho': {'name': 'Zoho Mail', 'imap_server': 'imappro.zoho.com', 'smtp_server': 'smtppro.zoho.com', 'smtp_port': 587},
    'yandex': {'name': 'Yandex.Mail', 'imap_server': 'imap.yandex.com', 'smtp_server': 'smtp.yandex.com', 'smtp_port': 587},
    'mail.ru': {'name': 'Mail.ru', 'imap_server': 'imap.mail.ru', 'smtp_server': 'smtp.mail.ru', 'smtp_port': 465, 'smtp_ssl': True},

    # Common Hosting Providers
    'ionos': {'name': 'IONOS by 1&1', 'imap_server': 'imap.ionos.com', 'smtp_server': 'smtp.ionos.com', 'smtp_port': 587},
    'bluehost': {'name': 'Bluehost', 'imap_server': 'box.bluehost.com', 'smtp_server': 'box.bluehost.com', 'smtp_port': 465, 'smtp_ssl': True},
    'hostgator': {'name': 'HostGator', 'imap_server': 'gator.hostgator.com', 'smtp_server': 'gator.hostgator.com', 'smtp_port': 465, 'smtp_ssl': True},
    'dreamhost': {'name': 'DreamHost', 'imap_server': 'imap.dreamhost.com', 'smtp_server': 'smtp.dreamhost.com', 'smtp_port': 465, 'smtp_ssl': True},
    'godaddy': {'name': 'GoDaddy', 'imap_server': 'imap.secureserver.net', 'smtp_server': 'smtpout.secureserver.net', 'smtp_port': 465, 'smtp_ssl': True},

}


# ==============================================================================
#  ADMIN-ONLY VIEWS
# ==============================================================================

@login_required
@admin_required
def admin_manage_email_config(request):
    """
    Allows an Admin to set the company-wide email server settings (IMAP/SMTP).
    These settings act as a template for all their managed users.
    """
    # Get or create the single configuration object for the logged-in admin.
    config, created = CompanyEmailConfig.objects.get_or_create(admin=request.user)

    if request.method == 'POST':
        form = CompanyEmailConfigForm(request.POST, instance=config)
        if form.is_valid():
            form.save()
            messages.success(request, "Company-wide email configuration has been successfully saved.")
            return redirect('accounts:admin_dashboard')
    else:
        form = CompanyEmailConfigForm(instance=config)

    context = {
        'form': form,
        'providers': EMAIL_PROVIDER_PRESETS,
        'provider_presets_json': json.dumps(EMAIL_PROVIDER_PRESETS),
        'title': 'Company Email Server Configuration'
    }
    return render(request, 'mail_monitor/admin_setup_form.html', context)


@login_required
@admin_required
def admin_email_inbox(request, user_id=None):
    """
    Displays a list of monitored emails.
    - If user_id is provided, it shows emails for ONLY that user.
    - If user_id is None:
        - SUPERADMIN sees emails from ALL users.
        - ADMIN sees emails ONLY from users they manage.
    """
    viewer = request.user
    email_queryset = MonitoredEmail.objects.select_related('account', 'account__user').all()
    title = 'Monitored Email Inbox'

    if user_id:
        target_user = get_object_or_404(CustomUser, pk=user_id)
        # Authorization check
        if viewer.role == CustomUser.ADMIN and target_user.company_admin != viewer:
            messages.error(request, "You are not authorized to view this user's emails.")
            return redirect('accounts:admin_dashboard')
        email_queryset = email_queryset.filter(account__user=target_user)
        title = f'Email Inbox for {target_user.get_full_name()}'
    elif viewer.role == CustomUser.ADMIN:
        managed_user_ids = CustomUser.objects.filter(company_admin=viewer).values_list('id', flat=True)
        email_queryset = email_queryset.filter(account__user__id__in=managed_user_ids)
        title = 'Global Inbox (Your Users)'

    context = {
        'emails': email_queryset.order_by('-date'),
        'title': title
    }
    return render(request, 'mail_monitor/admin_inbox.html', context)


@login_required
@admin_required
def admin_email_detail(request, email_id):
    """Displays the full details of a single email, with authorization."""
    viewer = request.user
    target_email = get_object_or_404(
        MonitoredEmail.objects.select_related('account__user').prefetch_related('attachments'), 
        pk=email_id
    )
    
    # --- THIS IS THE FIX ---
    # We now check against the correct 'is_superuser' attribute, which is
    # inherited from Django's AbstractUser model.
    is_authorized = (viewer.is_superuser) or (viewer.role == CustomUser.ADMIN and target_email.account.user.company_admin == viewer)
    
    if not is_authorized:
        messages.error(request, "You are not authorized to view this email.")
        return redirect('mail_monitor:admin_inbox')
    
    context = {
        'email': target_email,
        'title': f'Email: {target_email.subject}'
    }
    return render(request, 'mail_monitor/admin_email_detail.html', context)


# ==============================================================================
#  USER-ONLY VIEWS
# ==============================================================================

@login_required
@user_required
def user_setup_app_password(request):
    """
    Handles the user-facing form for submitting an App Password.

    This view will:
    1. Check if the user's admin has configured the company email settings.
    2. Display the form for the user to enter their App Password.
    3. On submission, remove any spaces from the password.
    4. Validate the credentials in real-time against the IMAP server.
    5. If valid, save the encrypted password and trigger the background listener.
    6. If invalid, display a clear error message to the user.
    """
    user = request.user

    # Prerequisite Check 1: User must be assigned to a company admin.
    if not user.company_admin:
        messages.error(request, "Your account is not assigned to a company admin. Please contact support.")
        return redirect('accounts:user_dashboard')

    # Prerequisite Check 2: The admin must have configured the email server settings.
    try:
        company_config = CompanyEmailConfig.objects.get(admin=user.company_admin)
    except CompanyEmailConfig.DoesNotExist:
        messages.warning(request, "Your company admin has not yet configured the email server settings. Please ask them to do so from their dashboard.")
        return redirect('accounts:user_dashboard')
        
    # Get the user's existing account to show the current status on the page.
    email_account = EmailAccount.objects.filter(user=user).first()
    
    # If the account exists and is marked as authenticated, redirect them away.
    if email_account and email_account.is_authenticated:
        return render(request, 'mail_monitor/already_authenticated.html')

    # If we get here, the user needs to set up their password.
    if request.method == 'POST':
        form = UserAppPasswordForm(request.POST)
        if form.is_valid():
            raw_password = form.cleaned_data['app_password'].replace(" ", "")
            
            # --- Real-time Validation ---
            is_valid, message = validate_imap_credentials(
                server=company_config.imap_server,
                port=company_config.imap_port,
                email=user.email,
                password=raw_password
            )

            if not is_valid:
                # On failure, we must ensure any old account is marked as unauthenticated.
                if email_account:
                    email_account.is_authenticated = False
                    email_account.save()
                messages.error(request, f"Authentication Failed: {message}. Please try again.")
            else:
                # --- On SUCCESS, save password and set the new flag ---
                account, created = EmailAccount.objects.get_or_create(user=user)
                account.set_password(raw_password)
                account.is_active = True
                account.is_authenticated = True # <-- SET THE AUTHENTICATED FLAG
                account.save()
                
                # Start the listener
                try:
                    channel_layer = get_channel_layer()
                    if channel_layer:
                        async_to_sync(channel_layer.send)(
                            "email-listener",
                            {"type": "start.listening", "account_id": account.id},
                        )
                        logger.info(f"Email listener start signal sent for account {account.id}")
                    else:
                        logger.warning("Channel layer not available - email listener may not start automatically")
                except Exception as e:
                    logger.error(f"Failed to send email listener start signal: {e}")
                
                messages.success(request, "Authentication successful! Your email monitoring is now active.")
                # Redirect to the same page, which will now show the "Already Authenticated" view.
                return redirect('mail_monitor:user_setup')
    else:
        form = UserAppPasswordForm()

    context = {
        'form': form,
        'title': 'Set Up Email Monitoring'
    }
    return render(request, 'mail_monitor/user_setup_form.html', context)


@login_required
@admin_required
def admin_monitoring_status(request):
    """
    Shows a list of all managed users and their email monitoring setup status.
    - SUPERADMIN sees all users.
    - ADMIN sees only their own managed users.
    """
    viewer = request.user
    
    # Base queryset for all standard users
    users_queryset = CustomUser.objects.filter(role=CustomUser.USER)

    # If the viewer is a regular ADMIN, filter to only their users
    if viewer.role == CustomUser.ADMIN:
        users_queryset = users_queryset.filter(company_admin=viewer)
    
    # Use select_related to efficiently fetch the related EmailAccount status
    # for each user in a single database query.
    users_with_status = users_queryset.select_related('email_account').order_by('first_name', 'last_name')

    context = {
        'users_with_status': users_with_status,
        'title': 'User Email Monitoring Status'
    }
    return render(request, 'mail_monitor/admin_monitoring_status.html', context)