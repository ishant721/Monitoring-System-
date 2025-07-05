# monitor_app/views.py

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
# --- ADD THIS IMPORT ---
from rest_framework_simplejwt.tokens import RefreshToken

# All other API views and imports from the previous correct versions are fine.
# This file only needs the HTML-rendering views updated.

class DashboardView(LoginRequiredMixin, TemplateView):
    """
    Serves the main activity monitoring dashboard HTML file.
    It now also generates a fresh API access token for the frontend JavaScript.
    """
    template_name = 'monitor_app/index.html' 
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Agent Activity Dashboard"
        
        # --- NEW LOGIC TO EMBED TOKEN ---
        # Generate a new access token for the logged-in user.
        try:
            if self.request.user.is_authenticated:
                refresh = RefreshToken.for_user(self.request.user)
                context['access_token'] = str(refresh.access_token)
                print(f"Generated access token for user {self.request.user.email}")
            else:
                context['access_token'] = None
                print("User not authenticated, no token generated")
        except Exception as e:
            # Handle cases where token generation might fail
            context['access_token'] = None
            print(f"Could not generate access token for user {self.request.user.email}: {e}")
            import traceback
            traceback.print_exc()
            
        return context
    
class KeyLoggerView(LoginRequiredMixin, TemplateView):
    """
    Serves the dedicated keylogger dashboard HTML file.
    It also generates a fresh API access token for the frontend JavaScript.
    """
    template_name = 'monitor_app/keylogger_dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Keystroke & IM Log Dashboard"
        
        # --- NEW LOGIC TO EMBED TOKEN ---
        try:
            refresh = RefreshToken.for_user(self.request.user)
            context['access_token'] = str(refresh.access_token)
        except Exception as e:
            context['access_token'] = None
            print(f"Could not generate access token for user {self.request.user.email}: {e}")

        return context

# ==============================================================================
#  ALL YOUR API VIEWS (from api/views.py) GO BELOW
# ==============================================================================
# These views do not need to change. Their security decorators correctly
# expect a token, which the frontend will now provide.

# from rest_framework.decorators import api_view, ...
# ...
# @api_view(['GET'])
# def agent_status_api_view(request): ...
# ... etc ...
class LiveStreamView(LoginRequiredMixin, TemplateView):
    """
    Serves the live video streaming page for admins to view agent screens in real-time
    """
    template_name = 'monitor_app/live_stream.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Live Screen Monitoring"
        
        # Generate access token for API calls
        try:
            refresh = RefreshToken.for_user(self.request.user)
            context['access_token'] = str(refresh.access_token)
        except Exception as e:
            context['access_token'] = None
            print(f"Could not generate access token for user {self.request.user.email}: {e}")
            
        return context
