# mail_monitor/routing.py
from django.urls import path
from . import consumers

channel_routing = {
    # This defines a channel name that our views can send messages to.
    # The 'email_listener' consumer will pick up messages sent to this channel.
    'email-listener': consumers.EmailListenerConsumer.as_asgi(),
}