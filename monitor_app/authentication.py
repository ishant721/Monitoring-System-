# monitor_app/authentication.py
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

class AgentAPIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        api_key = request.META.get('HTTP_X_API_KEY')
        agent_id = request.META.get('HTTP_X_AGENT_ID')

        if not api_key:
            return None

        # Check if it's a valid admin API key
        if api_key == settings.MASTER_API_KEY:
            # Create a fake user for the admin API key authentication
            admin_user = type('AdminUser', (), {
                'is_authenticated': True,
                'is_anonymous': False,
                'id': 'admin_api_key'
            })()

            # Set agent_id on request if provided
            if agent_id:
                request.agent_id = agent_id

            return (admin_user, None)

        return None