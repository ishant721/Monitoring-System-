# accounts/management/commands/check_admin_expirations.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from accounts.models import CustomUser 
from accounts.utils import send_admin_access_status_email # For notifying admin
import logging

logger = logging.getLogger("check_admin_expirations_command") 

class Command(BaseCommand):
    help = 'Checks for expired Admin access, updates status to EXPIRED, and triggers model save logic.'

    def handle(self, *args, **options):
        now = timezone.now()
        admins_to_check = CustomUser.objects.filter(
            role=CustomUser.ADMIN,
            is_active=True, 
            admin_account_type__in=[CustomUser.AdminAccountType.TRIAL, CustomUser.AdminAccountType.SUBSCRIBED],
            access_ends_at__isnull=False,
            access_ends_at__lt=now 
        ).exclude(admin_account_type=CustomUser.AdminAccountType.EXPIRED)

        if not admins_to_check.exists():
            self.stdout.write(self.style.SUCCESS('No admin accounts found needing expiry processing.'))
            return

        self.stdout.write(f"Found {admins_to_check.count()} admin accounts whose access period has ended...")
        processed_count = 0
        for admin in admins_to_check:
            self.stdout.write(f"Processing Admin: {admin.email} (ID: {admin.id}), current type: {admin.get_admin_account_type_display()}, access ends: {admin.access_ends_at}")
            try:
                admin.admin_account_type = CustomUser.AdminAccountType.EXPIRED
                # The model's save() method will set max_allowed_users to 0 and deactivate managed users.
                admin.save() 
                self.stdout.write(self.style.SUCCESS(f"Admin {admin.email} status updated to EXPIRED."))
                send_admin_access_status_email(admin) # Notify admin (no request object here)
                processed_count += 1
            except Exception as e:
                logger.error(f"Error processing expired admin {admin.email} (ID: {admin.id}): {e}", exc_info=True)
                self.stderr.write(self.style.ERROR(f"Failed to process admin {admin.email}: {e}"))
        
        self.stdout.write(self.style.SUCCESS(f'Finished processing. {processed_count} admin account(s) updated to EXPIRED.'))