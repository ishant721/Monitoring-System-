from django.urls import re_path
from . import consumers
from .streaming_consumers import LiveVideoStreamConsumer

websocket_urlpatterns = [
    re_path(r'ws/agent/(?P<agent_id>[\w-]+)/$', consumers.AgentConsumer.as_asgi()),
    re_path(r'ws/dashboard/$', consumers.DashboardConsumer.as_asgi()),
    re_path(r'ws/stream/(?P<user_type>\w+)/(?P<agent_id>[\w-]+)/$', LiveVideoStreamConsumer.as_asgi()),
    re_path(r'monitor/ws/stream/viewer/(?P<agent_id>[\w-]+)/$', LiveVideoStreamConsumer.as_asgi(), {'user_type': 'viewer'}),
]