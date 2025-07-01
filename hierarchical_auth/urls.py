
from django.contrib import admin
from django.urls import path, include
from django.views.generic.base import RedirectView
from django.conf import settings
from django.conf.urls.static import static
from django.urls import reverse_lazy
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    )

urlpatterns = [
    # --- Root URL Redirect ---
    # This redirects the base URL (e.g., http://127.0.0.1:8000/) to the login page.
    # This is a good user experience.
    path('', RedirectView.as_view(url=reverse_lazy('accounts:login'), permanent=False), name='home'),

    # --- Admin Site URL ---
    path('admin/', admin.site.urls),

    # --- Your Application URLs ---

    # Include all URLs from your user authentication app.
    # This will handle URLs like /accounts/login/, /accounts/dashboard/, etc.
    path('accounts/', include('accounts.urls', namespace='accounts')),

    # Include all URLs from your monitoring app.
    # This single line replaces the two old, incorrect 'monitoring' includes.
    # It will handle URLs like /monitor/dashboard/, /monitor/api/agents/status/, etc.
    path('monitor/', include('monitor_app.urls', namespace='monitor_app')),
    path('mail/', include('mail_monitor.urls')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]

# --- Media File Handling for Development ---
# This is a standard helper for serving user-uploaded media files (like screenshots
# and videos) when DEBUG is True. This should remain as is.
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)