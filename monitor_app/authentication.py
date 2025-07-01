# monitor_app/authentication.py
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

class AgentAPIKeyAuthentication(BaseAuthentication):
    """
    Custom authentication for agent API endpoints using API key and agent ID.
    """
    def authenticate(self, request):
        api_key = request.META.get('HTTP_X_API_KEY')
        agent_id = request.META.get('HTTP_X_AGENT_ID')

        if not api_key:
            return None

        # Validate API key (you can implement your own validation logic)
        expected_api_key = getattr(settings, 'AGENT_API_KEY', 'your-secret-api-key')
        if api_key != expected_api_key:
            raise AuthenticationFailed('Invalid API key')

        # Store agent_id in request for later use (even if None)
        request.agent_id = agent_id

        # Return a simple authentication tuple (no user object needed for agents)
        return (None, None)