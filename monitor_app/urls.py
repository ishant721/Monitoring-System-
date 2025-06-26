# monitor_app/urls.py

from django.urls import path, include
from . import views # Imports DashboardView and KeyLoggerView

app_name = 'monitor_app'

urlpatterns = [
    # --- HTML Page Views ---
    # These URLs are handled by the main views.py file above.
    
    # Resolves to /monitor/dashboard/
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    
    # Resolves to /monitor/keylogger/
    path('keylogger/', views.KeyLoggerView.as_view(), name='keylogger_dashboard'),

    # --- API URL Delegation ---
    # This single line is crucial for your organized structure. It tells Django
    # that any URL starting with /monitor/api/... should be handled by the
    # urls.py file inside the 'monitor_app/api/' folder.
    path('api/', include('monitor_app.api.urls')),
]