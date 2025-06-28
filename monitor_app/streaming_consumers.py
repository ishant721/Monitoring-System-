
import json
import base64
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.conf import settings
from .models import Agent
from accounts.models import CustomUser

logger = logging.getLogger(__name__)

class LiveVideoStreamConsumer(AsyncWebsocketConsumer):
    """
    Handles live video streaming from agents to admin dashboards
    """
    
    async def connect(self):
        self.agent_id = self.scope['url_route']['kwargs'].get('agent_id')
        self.user_type = self.scope['url_route']['kwargs'].get('user_type', 'viewer')
        
        if self.user_type == 'agent':
            # Check if live streaming is enabled for this agent
            if not await self.is_live_streaming_enabled():
                await self.close(code=4001)
                return
                
            # Agent streaming video
            self.stream_group = f'video_stream_{self.agent_id}'
            await self.channel_layer.group_add(self.stream_group, self.channel_name)
            await self.accept()
            logger.info(f"Agent {self.agent_id} connected for video streaming")
            
            # Update agent status
            await self.update_agent_streaming_status(True)
            
        elif self.user_type == 'viewer':
            # Admin viewing video
            user = self.scope.get('user')
            if user and await self.check_admin_permissions(user):
                self.stream_group = f'video_stream_{self.agent_id}'
                await self.channel_layer.group_add(self.stream_group, self.channel_name)
                await self.accept()
                logger.info(f"Admin {user.email} connected to view stream for agent {self.agent_id}")
            else:
                await self.close(code=4003)
        else:
            await self.close(code=4004)

    async def disconnect(self, close_code):
        if hasattr(self, 'stream_group'):
            await self.channel_layer.group_discard(self.stream_group, self.channel_name)
        
        if self.user_type == 'agent':
            await self.update_agent_streaming_status(False)
            logger.info(f"Agent {self.agent_id} disconnected from video streaming")

    async def receive(self, text_data=None, bytes_data=None):
        if self.user_type == 'agent' and bytes_data:
            # Agent sending video frame
            await self.channel_layer.group_send(
                self.stream_group,
                {
                    'type': 'video_frame',
                    'frame_data': base64.b64encode(bytes_data).decode('utf-8'),
                    'agent_id': self.agent_id
                }
            )
        elif text_data:
            try:
                data = json.loads(text_data)
                if data.get('type') == 'video_frame' and self.user_type == 'agent':
                    # Agent sending base64 encoded frame
                    await self.channel_layer.group_send(
                        self.stream_group,
                        {
                            'type': 'video_frame',
                            'frame_data': data.get('frame_data'),
                            'agent_id': self.agent_id
                        }
                    )
            except json.JSONDecodeError:
                pass

    async def video_frame(self, event):
        # Send video frame to viewers (admins)
        if self.user_type == 'viewer':
            await self.send(text_data=json.dumps({
                'type': 'video_frame',
                'frame_data': event['frame_data'],
                'agent_id': event['agent_id']
            }))

    @database_sync_to_async
    def check_admin_permissions(self, user):
        if not isinstance(user, CustomUser):
            return False
        
        if user.role in [CustomUser.SUPERADMIN, CustomUser.ADMIN]:
            try:
                agent = Agent.objects.get(agent_id=self.agent_id)
                if user.role == CustomUser.SUPERADMIN:
                    return True
                elif user.role == CustomUser.ADMIN and agent.user.company_admin == user:
                    return True
            except Agent.DoesNotExist:
                pass
        return False

    @database_sync_to_async
    def is_live_streaming_enabled(self):
        try:
            agent = Agent.objects.get(agent_id=self.agent_id)
            return agent.is_live_streaming_enabled
        except Agent.DoesNotExist:
            return False

    @database_sync_to_async
    def update_agent_streaming_status(self, is_streaming):
        try:
            agent = Agent.objects.get(agent_id=self.agent_id)
            agent.is_live_streaming = is_streaming
            if is_streaming:
                agent.live_stream_url = f"/monitor/stream/live/{self.agent_id}/"
            else:
                agent.live_stream_url = None
            agent.save(update_fields=['is_live_streaming', 'live_stream_url'])
        except Agent.DoesNotExist:
            logger.error(f"Agent {self.agent_id} not found when updating streaming status")
