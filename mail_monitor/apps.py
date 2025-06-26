from django.apps import AppConfig
import sys
import os

class MailMonitorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'mail_monitor'

    def ready(self):
        """
        This method is called by Django when the application is fully loaded.
        It's the ideal place to start background services.
        """
        # These checks are crucial. They ensure this code only runs ONCE when
        # the main server process starts, not multiple times during development
        # due to the autoreloader, and not during other management commands.
        is_running_server = any(cmd in sys.argv for cmd in ['runserver', 'daphne'])
        is_main_process = os.environ.get('RUN_MAIN') != 'true'

        if is_running_server and is_main_process:
            # We import here to avoid circular dependency issues at startup.
            from .consumers import start_all_listeners_in_thread
            
            print("--- Mail Monitor App is ready. Initializing background email listeners... ---")
            start_all_listeners_in_thread()