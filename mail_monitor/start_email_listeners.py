
from django.core.management.base import BaseCommand
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from mail_monitor.models import EmailAccount
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Manually start email listeners for all authenticated accounts'

    def handle(self, *args, **options):
        authenticated_accounts = EmailAccount.objects.filter(
            is_active=True, 
            is_authenticated=True
        )
        
        self.stdout.write(f"Found {authenticated_accounts.count()} authenticated accounts")
        
        channel_layer = get_channel_layer()
        if not channel_layer:
            self.stderr.write("Channel layer not available")
            return
            
        started_count = 0
        for account in authenticated_accounts:
            try:
                async_to_sync(channel_layer.send)(
                    "email-listener",
                    {"type": "start.listening", "account_id": account.id}
                )
                self.stdout.write(f"Started listener for {account.user.email}")
                started_count += 1
            except Exception as e:
                self.stderr.write(f"Failed to start listener for {account.user.email}: {e}")
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully started {started_count} email listeners')
        )
