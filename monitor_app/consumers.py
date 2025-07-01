# monitor_app/consumers.py

import json
import traceback
import time
import base64
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from django.core.files.base import ContentFile
from django.db import transaction
from django.conf import settings
import logging

# Use Django's logging for better, more detailed output
logger = logging.getLogger(__name__)

from .models import Agent, AgentData, KeyLog
from accounts.models import CustomUser


# =====================================================================
#  AGENT CONSUMER (CORRECTED AND ROBUST)
# =====================================================================
class AgentConsumer(AsyncJsonWebsocketConsumer):
    """
    Handles WebSocket connections, including automated pairing and processing of monitoring data.
    """

    async def connect(self):
        self.agent_id = self.scope['url_route']['kwargs'].get('agent_id', 'unpaired')
        self.agent_group_name = f'agent_{self.agent_id}'
        self.dashboard_group = 'dashboard_status'
        self.scope['authenticated'] = False
        await self.channel_layer.group_add(self.agent_group_name, self.channel_name)
        await self.accept()
        logger.info(f"Agent connection received. ID/URL Param: '{self.agent_id}'. Awaiting message.")

    async def disconnect(self, close_code):
        logger.info(f"Agent {self.agent_id} DISCONNECTED (Code: {close_code}).")
        if self.scope.get('authenticated'):
            await self.update_agent_on_disconnect()
            await self.notify_dashboard_of_status_update(is_online=False)
        await self.channel_layer.group_discard(self.agent_group_name, self.channel_name)

    async def receive_json(self, content):
        """
        Handles all incoming WebSocket messages from agents including control responses.
        """
        try:
            message_type = content.get('type')

            if message_type == 'pair_agent':
                await self.handle_pairing(content)
                return

            if not self.scope.get('authenticated'):
                await self.handle_authentication(content)
                return

            if message_type == 'heartbeat':
                await self.process_heartbeat(content)
            elif message_type == 'key_log':
                await self.process_key_log(content)
            elif message_type == 'control_response':
                await self.process_control_response(content)

        except Exception as e:
            logger.error(f"Error processing WebSocket message for agent {self.agent_id}: {e}", exc_info=True)

    async def handle_pairing(self, content):
        pairing_token = content.get('pairing_token')
        new_agent_id = content.get('agent_id')
        if not pairing_token or not new_agent_id:
            await self.close(code=4005, reason="Token and Agent ID required")
            return

        success = await self.pair_agent_with_user(pairing_token, new_agent_id)
        if success:
            await self.send_json({"type": "pairing_success", "agent_id": new_agent_id})
            await self.close(code=1000)
        else:
            await self.send_json({"type": "pairing_failed"})
            await self.close(code=4006, reason="Pairing failed. Invalid token or ID already exists.")

    async def handle_authentication(self, content):
        if content.get('type') == 'auth' and content.get('api_key') == settings.AGENT_API_KEY:
            if await self.verify_agent_registration():
                self.scope['authenticated'] = True
                logger.info(f"SUCCESS: Agent {self.agent_id} authenticated.")
                await self.notify_dashboard_of_status_update(is_online=True)
            else:
                logger.warning(f"Auth failed for agent '{self.agent_id}': Not found in database.")
                await self.close(code=4004, reason="Unregistered agent ID")
        else:
            logger.warning(f"Auth failed for agent '{self.agent_id}': Invalid type or API key.")
            await self.close(code=4003, reason="Authentication failed")

    # FIX: Add the missing verify_agent_registration method back into the class.
    @database_sync_to_async
    def verify_agent_registration(self):
        """Checks if an agent with the given ID exists in the database."""
        return Agent.objects.filter(agent_id=self.agent_id).exists()

    @database_sync_to_async
    @transaction.atomic
    def process_key_log(self, data):
        agent_id = data.get('agent_id')
        key_sequence = data.get('key_sequence')
        source_app = data.get('source_app', 'Unknown Source')

        logger.info(f"🔍 PROCESSING KEY_LOG: agent_id={agent_id}, source_app={source_app}, key_length={len(key_sequence) if key_sequence else 0}")

        if not agent_id or not key_sequence:
            logger.warning("[CONSUMER] Received key_log with missing agent_id or key_sequence. Discarding.")
            return

        try:
            agent = Agent.objects.get(agent_id=agent_id)
            keylog = KeyLog.objects.create(
                agent=agent,
                source_app=source_app,
                key_sequence=key_sequence,
                is_messaging_log=bool(data.get('is_messaging', False))
            )
            logger.info(f"✅ Successfully saved KeyLog ID {keylog.id} for agent {agent_id}")
        except Agent.DoesNotExist:
            logger.error(f"❌ FAILED to save KeyLog: Agent with ID {agent_id} not found.")
        except Exception as e:
            logger.error(f"❌ FAILED to process keylog for {agent_id}. Error: {e}", exc_info=True)

    @database_sync_to_async
    @transaction.atomic
    def process_heartbeat(self, data):
        agent_id = data.get('agent_id')
        if not agent_id:
            logger.warning("[CONSUMER] Received heartbeat with no agent_id. Discarding.")
            return

        try:
            screenshot_file = None
            if raw_base64_data := data.get('screenshot'):
                try:
                    padded_base64 = raw_base64_data + '=' * (-len(raw_base64_data) % 4)
                    decoded_file_bytes = base64.b64decode(padded_base64)
                    screenshot_file = ContentFile(decoded_file_bytes, name=f'ss_{int(time.time())}.png')
                except Exception as e:
                    logger.warning(f"Could not decode screenshot for {agent_id}: {e}")

            Agent.objects.update_or_create(
                agent_id=agent_id,
                defaults={
                    'last_seen': timezone.now(),
                    'window_title': data.get('window_title', ''),
                    'active_browser_url': data.get('active_browser_url', ''),
                    'is_recording': data.get('is_recording', False),
                }
            )

            AgentData.objects.create(
                agent_id=agent_id,
                window_title=data.get('window_title'),
                active_browser_url=data.get('active_browser_url'),
                keystroke_count=int(data.get('keystroke_count', 0)),
                mouse_event_count=int(data.get('mouse_event_count', 0)),
                upload_bytes=int(data.get('upload_bytes', 0)),
                download_bytes=int(data.get('download_bytes', 0)),
                network_type=data.get('network_type'),
                productive_status=data.get('productive_status'),
                screenshot=screenshot_file,
                is_activity_monitoring_enabled=data.get('is_activity_monitoring_enabled', True),
                is_network_monitoring_enabled=data.get('is_network_monitoring_enabled', True),
                capture_interval_seconds=int(data.get('current_interval_seconds', 10))
            )

        except Exception as e:
            logger.error(f"❌ FAILED to process heartbeat for {agent_id}. Error: {e}", exc_info=True)

    async def control_command(self, event):
        if not self.scope.get('authenticated'):
            logger.warning(f"Cannot send control command to unauthenticated agent {self.agent_id}")
            return

        control_msg = event.copy()
        control_msg['type'] = 'control'

        try:
            await self.send_json(control_msg)
            logger.info(f"Control command sent to agent {self.agent_id}")
        except Exception as e:
            logger.error(f"Failed to send control command to agent {self.agent_id}: {e}")

    async def process_control_response(self, data):
        logger.info(f"Control response from {self.agent_id}: {data}")
        await self.channel_layer.group_send(
            self.dashboard_group,
            {
                "type": "agent_control_feedback",
                "agent_id": self.agent_id,
                "response_data": data
            }
        )

    async def notify_dashboard_of_status_update(self, is_online=True):
        agent_status = await self.get_agent_status_for_dashboard(is_online)
        if agent_status:
            await self.channel_layer.group_send(
                self.dashboard_group,
                {'type': 'agent_status_update', 'agent_data': agent_status}
            )

    @database_sync_to_async
    def get_agent_status_for_dashboard(self, is_online):
        try:
            agent = Agent.objects.select_related('user').get(agent_id=self.agent_id)
            return {
                "agent_id": agent.agent_id,
                "user_email": agent.user.email,
                "is_online": is_online,
                "last_seen": agent.last_seen.isoformat(),
                "is_recording": agent.is_recording,
                "window_title": agent.window_title,
                "active_browser_url": agent.active_browser_url,
            }
        except Agent.DoesNotExist:
            return None

    @database_sync_to_async
    def update_agent_on_disconnect(self):
        Agent.objects.filter(agent_id=self.agent_id).update(is_recording=False)

    @database_sync_to_async
    @transaction.atomic
    def pair_agent_with_user(self, pairing_token, new_agent_id):
        try:
            user_to_pair = CustomUser.objects.get(agent_pairing_token=pairing_token, agent_pairing_token_expires__gt=timezone.now())
            if Agent.objects.filter(agent_id=new_agent_id).exists(): return False
            Agent.objects.create(user=user_to_pair, agent_id=new_agent_id, last_seen=timezone.now())
            user_to_pair.agent_pairing_token = None
            user_to_pair.agent_pairing_token_expires = None
            user_to_pair.save(update_fields=['agent_pairing_token', 'agent_pairing_token_expires'])
            return True
        except Exception as e:
            logger.error(f"Error during agent pairing process: {e}", exc_info=True)
            return False


# =====================================================================
#  DASHBOARD CONSUMER (WITH NEW FEEDBACK HANDLER)
# =====================================================================
class DashboardConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.dashboard_group_name = 'dashboard_status'
        await self.channel_layer.group_add(self.dashboard_group_name, self.channel_name)
        await self.accept()
        await self.send_all_agent_statuses()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.dashboard_group_name, self.channel_name)

    async def agent_status_update(self, event):
        await self.send_json(event)

    async def agent_control_feedback(self, event):
        await self.send_json(event)

    async def send_all_agent_statuses(self):
        all_statuses = await self.get_all_agent_data_from_db()
        await self.send_json({"type": "all_agents_status", "agents": all_statuses})

    @database_sync_to_async
    def get_all_agent_data_from_db(self):
        agents_data = []
        timeout = getattr(settings, 'AGENT_ONLINE_TIMEOUT_SECONDS', 30)
        for agent in Agent.objects.select_related('user').all().order_by('user__email'):
            is_online = (timezone.now() - agent.last_seen).total_seconds() < timeout
            agents_data.append({
                "agent_id": agent.agent_id,
                "user_email": agent.user.email,
                "is_online": is_online,
                "last_seen": agent.last_seen.isoformat(),
                "is_recording": agent.is_recording,
                "window_title": agent.window_title,
                "active_browser_url": agent.active_browser_url
            })
        return agents_data

# Adding MonitoringConsumer from the changes, placed after DashboardConsumer since it's another type of consumer.
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .models import Agent

User = get_user_model()

class MonitoringConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Get the agent_id from the URL route
        self.agent_id = self.scope['url_route']['kwargs']['agent_id']
        self.room_group_name = f'monitoring_{self.agent_id}'

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()
        print(f"WebSocket connected for agent: {self.agent_id}")

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
        print(f"WebSocket disconnected for agent: {self.agent_id}")

    # Receive message from WebSocket
    async def receive(self, text_data):
        try:
            text_data_json = json.loads(text_data)
            message_type = text_data_json.get('type')

            if message_type == 'agent_status':
                await self.handle_agent_status(text_data_json)
            elif message_type == 'screen_data':
                await self.handle_screen_data(text_data_json)
            elif message_type == 'keystroke_data':
                await self.handle_keystroke_data(text_data_json)

        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'error': 'Invalid JSON format'
            }))

    async def handle_agent_status(self, data):
        # Update agent status in database
        await self.update_agent_status(data)

        # Send message to room group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'agent_status_update',
                'data': data
            }
        )

    async def handle_screen_data(self, data):
        # Process screen data
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'screen_update',
                'data': data
            }
        )

    async def handle_keystroke_data(self, data):
        # Process keystroke data
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'keystroke_update',
                'data': data
            }
        )

    # Receive message from room group
    async def agent_status_update(self, event):
        data = event['data']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'agent_status_update',
            'data': data
        }))

    async def screen_update(self, event):
        data = event['data']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'screen_update',
            'data': data
        }))

    async def keystroke_update(self, event):
        data = event['data']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'keystroke_update',
            'data': data
        }))

    @database_sync_to_async
    def update_agent_status(self, data):
        try:
            agent = Agent.objects.get(id=self.agent_id)
            agent.is_active = data.get('is_active', True)
            agent.last_seen = data.get('timestamp')
            agent.save()
        except Agent.DoesNotExist:
            pass