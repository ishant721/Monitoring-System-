# monitor_app/authentication.py
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

class AgentAPIKeyAuthentication(BaseAuthentication):
    """
    Custom authentication for agent API endpoints using API key and agent ID.
    """
    def authenticate(self, request):
        # Get the API key from the Authorization header or X-API-KEY header
        api_key = None

        # Try Authorization header first (Bearer token format)
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith('Bearer '):
            api_key = auth_header[7:]  # Remove 'Bearer ' prefix

        # Fall back to X-API-KEY header
        if not api_key:
            api_key = request.META.get('HTTP_X_API_KEY')

        if not api_key:
            return None

        # Validate the API key against MASTER_API_KEY
        expected_key = getattr(settings, 'MASTER_API_KEY', getattr(settings, 'AGENT_API_KEY', ''))
        if api_key != expected_key:
            raise AuthenticationFailed('Invalid API key')

        # Get agent ID from header
        agent_id = request.META.get('HTTP_X_AGENT_ID')
        if not agent_id:
            raise AuthenticationFailed('Agent ID header is required')

        # Verify agent exists in database
        try:
            agent = Agent.objects.get(agent_id=agent_id)
        except Agent.DoesNotExist:
            raise AuthenticationFailed(f'Agent {agent_id} not found')

        # Set agent_id on request for use in views
        request.agent_id = agent_id

        # Return a dummy user and token (API key authentication doesn't use Django users)
        return (agent.user if agent.user else AnonymousUser(), api_key)