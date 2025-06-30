"""
ASGI config for hierarchical_auth project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import monitor_app.routing
import mail_monitor.routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hierarchical_auth.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter([
            *monitor_app.routing.websocket_urlpatterns,
            *mail_monitor.routing.websocket_urlpatterns,
        ])
    ),
})