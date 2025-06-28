
import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter, ChannelNameRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path, re_path

# Import the routing configurations from BOTH of your apps
import monitor_app.routing
import monitor_app.consumers
import monitor_app.streaming_consumers
from mail_monitor.routing import channel_routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hierarchical_auth.settings')

application = ProtocolTypeRouter({
    
    "http": get_asgi_application(),

    # WebSocket routing - handle monitor/ws/ paths directly
    "websocket": AuthMiddlewareStack(
        URLRouter([
            re_path(r'^monitor/ws/agent/(?P<agent_id>[\w-]+)/$', monitor_app.consumers.AgentConsumer.as_asgi()),
            re_path(r'^monitor/ws/dashboard/$', monitor_app.consumers.DashboardConsumer.as_asgi()),
            re_path(r'^monitor/ws/stream/(?P<user_type>\w+)/(?P<agent_id>[\w-]+)/$', monitor_app.streaming_consumers.LiveVideoStreamConsumer.as_asgi()),
        ])
    ),
    
    "channel": ChannelNameRouter(
        channel_routing
    ),
})
