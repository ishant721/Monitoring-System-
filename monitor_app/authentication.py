# monitor_app/authentication.py
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

class AgentAPIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('ApiKey '):
            return None

        provided_key = auth_header.split(' ')[1]
        if provided_key != settings.AGENT_API_KEY:
            raise AuthenticationFailed('Invalid API Key.')
        
        # Successful authentication for a system, not a user.
        return (None, None)