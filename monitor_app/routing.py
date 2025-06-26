# monitor_app/routing.py

from django.urls import path
from . import consumers

# This list defines all the WebSocket URL patterns for this app.
# Your project's asgi.py will include this list.
websocket_urlpatterns = [
    # This pattern handles connections from the individual desktop agents.
    # The URL will look like: ws://yourdomain.com/monitor/ws/agent/{agent_id}/
    path('monitor/ws/agent/<str:agent_id>/', consumers.AgentConsumer.as_asgi()),
    
    # This pattern handles connections from the web dashboard UI for live updates.
    # The URL will look like: ws://yourdomain.com/monitor/ws/dashboard/
    path('monitor/ws/dashboard/', consumers.DashboardConsumer.as_asgi()),
]