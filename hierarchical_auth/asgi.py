# hierarchical_auth/asgi.py

import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter, ChannelNameRouter
from channels.auth import AuthMiddlewareStack

# Import the routing configurations from BOTH of your apps
import monitor_app.routing
from mail_monitor.routing import channel_routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hierarchical_auth.settings')

application = ProtocolTypeRouter({
    
    "http": get_asgi_application(),

    # --- THIS IS THE FIX ---
    # We pass the websocket_urlpatterns directly to the main URLRouter.
    # We remove the extra path("monitor/", ...) nesting.
    "websocket": AuthMiddlewareStack(
        URLRouter(
            monitor_app.routing.websocket_urlpatterns
        )
    ),
    
    "channel": ChannelNameRouter(
        channel_routing
    ),
})