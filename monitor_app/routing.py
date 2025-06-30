from django.urls import re_path
from .consumers import AgentConsumer, DashboardConsumer, MonitoringConsumer
from .streaming_consumers import LiveVideoStreamConsumer

websocket_urlpatterns = [
    re_path(r'monitor/ws/agent/(?P<agent_id>[^/]+)/$', AgentConsumer.as_asgi()),
    re_path(r'ws/monitor/agent/(?P<agent_id>[^/]+)/$', AgentConsumer.as_asgi()),
    re_path(r'ws/monitor/dashboard/$', DashboardConsumer.as_asgi()),
    re_path(r'ws/monitor/live/(?P<agent_id>[^/]+)/$', MonitoringConsumer.as_asgi()),
    re_path(r'ws/stream/agent/(?P<agent_id>[^/]+)/$', LiveVideoStreamConsumer.as_asgi(), {'user_type': 'agent'}),
    re_path(r'ws/stream/viewer/(?P<agent_id>[^/]+)/$', LiveVideoStreamConsumer.as_asgi(), {'user_type': 'viewer'}),
]