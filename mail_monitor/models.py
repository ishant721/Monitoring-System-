# mail_monitor/models.py

from django.db import models
from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken
import os

def attachment_upload_path(instance, filename):
    """
    Generates a unique path for each attachment to avoid filename conflicts.
    Example: MEDIA_ROOT/mail_attachments/admin_username/user_email/2025/06/email_id/attachment.pdf
    """
    account = instance.email.account
    email_date = instance.email.date
    # Added defensive checks to prevent errors if any part of the path is missing
    if not (account and account.user and email_date and instance.email.id):
        return os.path.join('mail_attachments', 'uncategorized', filename) # Use os.path.join for cross-platform compatibility
    
    admin_username = account.user.company_admin.username if account.user.company_admin else 'no_admin'
    return os.path.join(
        'mail_attachments',
        admin_username,
        account.user.email,
        str(email_date.year),
        str(email_date.month),
        str(instance.email.id),
        filename
    )

class CompanyEmailConfig(models.Model):
    """Stores the company-wide IMAP server settings, configured by an Admin."""
    admin = models.OneToOneField(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE,
        limit_choices_to={'role': 'ADMIN'},
        related_name='email_config',
        help_text="The Admin user who owns this configuration."
    )
    imap_server = models.CharField(max_length=255) # Increased length for longer domain names
    imap_port = models.PositiveIntegerField(default=993)
    smtp_server = models.CharField(max_length=255, blank=True, null=True) # Increased length
    smtp_port = models.PositiveIntegerField(default=587, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Email Server Config for {self.admin.email}"

    class Meta:
        verbose_name = "Company Email Configuration"
        verbose_name_plural = "Company Email Configurations"


class EmailAccount(models.Model):
    """Stores the encrypted App Password and sync status for a single monitored User."""
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='email_account')
    encrypted_app_password = models.CharField(max_length=512) # Increased length for different encryption algorithms
    
    is_active = models.BooleanField(default=True, help_text="Controlled by the Admin's activate/deactivate actions.")
    is_authenticated = models.BooleanField(default=False, help_text="True if a successful IMAP login has occurred with the stored credentials.")
    
    last_inbox_uid = models.PositiveIntegerField(null=True, blank=True, help_text="The UID of the last email fetched from the inbox.")
    last_sent_uid = models.PositiveIntegerField(null=True, blank=True, help_text="The UID of the last email fetched from the sent folder.")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def set_password(self, raw_password):
        f = Fernet(settings.EMAIL_ENCRYPTION_KEY)
        self.encrypted_app_password = f.encrypt(raw_password.encode()).decode()

    def get_decrypted_password(self):
        f = Fernet(settings.EMAIL_ENCRYPTION_KEY)
        try:
            return f.decrypt(self.encrypted_app_password.encode()).decode()
        except (InvalidToken, TypeError, ValueError):
            return None

    def __str__(self):
        return f"Email Credentials for {self.user.email}"
    
    class Meta:
        verbose_name = "User Email Account"
        verbose_name_plural = "User Email Accounts"


class MonitoredEmail(models.Model):
    """Stores the full, detailed content of a single fetched email."""
    class Direction(models.TextChoices):
        INCOMING = 'IN', 'Incoming'
        OUTGOING = 'OUT', 'Outgoing'

    account = models.ForeignKey("EmailAccount", on_delete=models.CASCADE, related_name="emails")
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='replies')
    in_reply_to_header = models.CharField(max_length=512, blank=True, null=True, db_index=True)
    message_id = models.CharField(max_length=512, unique=True, db_index=True) # Increased length
    direction = models.CharField(max_length=3, choices=Direction.choices, db_index=True) # Added db_index for faster filtering
    sender = models.TextField() # Changed to TextField for long sender names/addresses
    recipients_to = models.TextField(blank=True)
    recipients_cc = models.TextField(blank=True)
    recipients_bcc = models.TextField(blank=True)
    subject = models.TextField(blank=True) # Changed to TextField for very long subjects
    body = models.TextField(blank=True)
    date = models.DateTimeField(db_index=True) # Added db_index for faster sorting
    has_attachments = models.BooleanField(default=False)
    fetched_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.subject or "(No Subject)"

    class Meta:
        ordering = ['-date'] # Order by most recent first, which is more common for inboxes
        verbose_name = "Monitored Email"
        verbose_name_plural = "Monitored Emails"


class EmailAttachment(models.Model):
    """Stores a single file attachment related to a MonitoredEmail."""
    email = models.ForeignKey(MonitoredEmail, on_delete=models.CASCADE, related_name="attachments")
    file = models.FileField(upload_to=attachment_upload_path)
    filename = models.CharField(max_length=255)
    content_type = models.CharField(max_length=255) # Increased length

    def __str__(self):
        return self.filename
    
    class Meta:
        verbose_name = "Email Attachment"
        verbose_name_plural = "Email Attachments"