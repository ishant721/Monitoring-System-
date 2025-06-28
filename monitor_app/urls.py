from django.urls import path, include
from .views import DashboardView, KeyLoggerView, LiveStreamView

app_name = 'monitor_app'

urlpatterns = [
    path('', DashboardView.as_view(), name='dashboard'),
    path('keylogger/', KeyLoggerView.as_view(), name='keylogger_dashboard'),
    path('live_stream/', LiveStreamView.as_view(), name='live_stream'),
    path('api/', include('monitor_app.api.urls')),
]