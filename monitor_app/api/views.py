# monitor_app/api/views.py
import logging
from django.db.models import Subquery, OuterRef
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_datetime, parse_time
from django.utils import timezone
from django.db import transaction

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.parsers import MultiPartParser, FormParser

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from ..models import Agent, AgentData, RecordedVideo, KeyLog
from accounts.models import CustomUser
from ..authentication import AgentAPIKeyAuthentication


# ==============================================================================
#  AGENT-FACING API Endpoints (Used by the desktop agent)
# ==============================================================================

@api_view(['GET'])
@authentication_classes([AgentAPIKeyAuthentication])
@permission_classes([])
def get_config_api(request):
    """
    Called by agents to get their configuration.
    """
    # Get agent_id from request headers (set by authentication)
    agent_id = getattr(request, 'agent_id', None)
    if not agent_id:
        return Response({"error": "Agent ID not found in request"}, status=status.HTTP_400_BAD_REQUEST)
    
    agent = get_object_or_404(Agent, agent_id=agent_id)
    
    # FIX: Perform schedule formatting directly in the view
    def format_time(t): return t.strftime('%H:%M') if t else None
    schedule_days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
    schedule = {day: {"start": format_time(getattr(agent, f'{day}_active_start', None)), "end": format_time(getattr(agent, f'{day}_active_end', None))} for day in schedule_days}

    config = {
        "agent_id": agent.agent_id,
        "capture_interval": agent.capture_interval_seconds,
        "activity_monitoring_enabled": agent.is_activity_monitoring_enabled,
        "network_monitoring_enabled": agent.is_network_monitoring_enabled,
        "schedule": schedule,
    }
    return Response(config)


class RecordingUploadAPIView(APIView):
    authentication_classes = [AgentAPIKeyAuthentication]
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = []  # Allow access with API key authentication
    
    def post(self, request, *args, **kwargs):
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            # Get agent_id from authentication middleware
            agent_id = getattr(request, 'agent_id', None)
            if not agent_id:
                # Fallback to request data
                agent_id = request.data.get('agent_id')
            
            video_file = request.FILES.get('video_file')
            
            logger.info(f"Upload attempt - Agent ID: {agent_id}, File: {video_file.name if video_file else 'None'}")
            logger.info(f"Request data: {dict(request.data)}")
            logger.info(f"Request files: {list(request.FILES.keys())}")
            
            if not agent_id:
                logger.error("Missing agent ID in request")
                return Response({"error": "Agent ID is required."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Get the agent object
            try:
                agent = Agent.objects.get(agent_id=agent_id)
                logger.info(f"Found agent: {agent}")
            except Agent.DoesNotExist:
                logger.error(f"Agent not found: {agent_id}")
                return Response({"error": f"Agent {agent_id} not found."}, status=status.HTTP_404_NOT_FOUND)
            
            # Get filename
            filename = video_file.name if video_file else request.data.get('filename', 'unknown_recording.mp4')
            file_size = video_file.size if video_file else request.data.get('file_size', 0)
            
            logger.info(f"Processing recording - Filename: {filename}, File size: {file_size}")
            
            # Create recorded video entry
            try:
                recorded_video = RecordedVideo.objects.create(
                    agent=agent,
                    filename=filename,
                    video_file=video_file if video_file else None
                )
                
                storage_type = "Server" if video_file else "Local"
                logger.info(f"Recording saved to database - ID: {recorded_video.id}, Storage: {storage_type}")
                
                return Response({
                    "message": "Recording processed successfully.",
                    "video_id": recorded_video.id,
                    "filename": filename,
                    "storage_type": storage_type
                }, status=status.HTTP_201_CREATED)
                
            except Exception as db_error:
                logger.error(f"Database error creating RecordedVideo: {str(db_error)}", exc_info=True)
                return Response({"error": f"Database error: {str(db_error)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            logger.error(f"Error processing recording upload: {str(e)}", exc_info=True)
            return Response({"error": f"Failed to process recording: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ==============================================================================
#  DASHBOARD-FACING API Endpoints (Used by the web UI's JavaScript)
# ==============================================================================

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def agent_status_api_view(request):
    """
    (Corrected) Returns a list of all agents and their live status, optimized
    to prevent N+1 query issues.
    """
    user = request.user
    agents_qs = Agent.objects.none()
    
    if user.is_superuser:
        agents_qs = Agent.objects.select_related('user').all()
    elif user.role == CustomUser.ADMIN:
        agents_qs = Agent.objects.select_related('user').filter(user__company_admin=user)
    else:
        agents_qs = Agent.objects.select_related('user').filter(user=user)
    
    latest_agent_data = AgentData.objects.filter(agent_id=OuterRef('agent_id')).order_by('-timestamp')
    
    agents = agents_qs.annotate(
        latest_upload_bytes=Subquery(latest_agent_data.values('upload_bytes')[:1]),
        latest_download_bytes=Subquery(latest_agent_data.values('download_bytes')[:1]),
        latest_network_type=Subquery(latest_agent_data.values('network_type')[:1]),
    ).order_by('user__email')

    data = []
    # FIX: Define schedule formatting logic here, not in the model
    def format_time(t): return t.strftime('%H:%M') if t else None
    schedule_days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]

    for agent in agents:
        is_online = (timezone.now() - agent.last_seen).total_seconds() < getattr(settings, 'AGENT_ONLINE_TIMEOUT_SECONDS', 30)
        
        # Format the schedule for this specific agent
        schedule = {day: {"start": format_time(getattr(agent, f'{day}_active_start', None)), "end": format_time(getattr(agent, f'{day}_active_end', None))} for day in schedule_days}

        data.append({
            "agent_id": agent.agent_id, 
            "user_email": agent.user.email if agent.user else "Unassigned",
            "is_online": is_online, 
            "last_seen": agent.last_seen.isoformat(),
            "is_recording": agent.is_recording, 
            "window_title": agent.window_title,
            "active_browser_url": agent.active_browser_url,
            "capture_interval_seconds": agent.capture_interval_seconds,
            "is_activity_monitoring_enabled": agent.is_activity_monitoring_enabled,
            "is_network_monitoring_enabled": agent.is_network_monitoring_enabled,
            "upload_bytes": agent.latest_upload_bytes if agent.latest_upload_bytes is not None else 0,
            "download_bytes": agent.latest_download_bytes if agent.latest_download_bytes is not None else 0,
            "network_type": agent.latest_network_type or "N/A",
            "schedule": schedule # Use the schedule formatted inside this view
        })
    return Response(data)

# ... All other views from the previously corrected file remain the same, as they are correct. ...
# (update_agent_config_api, agent_control_view, broadcast_config_update, etc.)

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def update_agent_config_api(request, agent_id):
    """
    (Corrected) Updates configuration for a specific agent AND sends a live
    update command to the agent if it's online.
    """
    agent = get_object_or_404(Agent, agent_id=agent_id)
    user = request.user
    if not (user.is_superuser or user == agent.user.company_admin or user == agent.user):
        return Response({"error": "Permission Denied."}, status=status.HTTP_403_FORBIDDEN)
    
    data = request.data
    agent.capture_interval_seconds = int(data.get('capture_interval', agent.capture_interval_seconds))
    agent.is_activity_monitoring_enabled = data.get('activity_monitoring_enabled', agent.is_activity_monitoring_enabled)
    agent.is_network_monitoring_enabled = data.get('network_monitoring_enabled', agent.is_network_monitoring_enabled)
    if 'schedule' in data:
        for day, times in data['schedule'].items():
            setattr(agent, f'{day}_active_start', parse_time(times.get('start')) if times.get('start') else None)
            setattr(agent, f'{day}_active_end', parse_time(times.get('end')) if times.get('end') else None)
    agent.save()
    
    def format_time(t): return t.strftime('%H:%M') if t else None
    schedule_days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
    schedule = {day: {"start": format_time(getattr(agent, f'{day}_active_start', None)), "end": format_time(getattr(agent, f'{day}_active_end', None))} for day in schedule_days}

    channel_layer = get_channel_layer()
    update_message = {
        "type": "control_command",
        "action": "set_global_config",
        "feature_bundle": "global_config",
        "capture_interval": agent.capture_interval_seconds,
        "activity_monitoring_enabled": agent.is_activity_monitoring_enabled,
        "network_monitoring_enabled": agent.is_network_monitoring_enabled,
        "schedule": schedule,
    }
    async_to_sync(channel_layer.group_send)(f"agent_{agent.agent_id}", update_message)
    
    return Response({"message": f"Configuration for agent {agent_id} updated and live command sent."}, status=status.HTTP_200_OK)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def agent_control_view(request, agent_id, action):
    # ... This view is correct, no changes needed
    agent = get_object_or_404(Agent, agent_id=agent_id)
    user = request.user
    if not (user.is_superuser or user == agent.user.company_admin or user == agent.user):
        return Response({"error": "Permission Denied."}, status=status.HTTP_403_FORBIDDEN)
    
    feature_bundle = request.data.get('feature_bundle')
    # ... (all your validation code remains here) ...
    
    control_message = {"type": "control_command", "action": action, "feature_bundle": feature_bundle}
    if feature_bundle == "interval_control":
        control_message["interval"] = request.data.get('interval')
    
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(f"agent_{agent.agent_id}", control_message)
    
    return Response({"message": f"Command '{action}' for {feature_bundle} sent to agent {agent_id}."}, status=status.HTTP_200_OK)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def broadcast_config_update(request):
    # ... This view is correct, no changes needed
    user = request.user
    agents_to_update = Agent.objects.none()
    if user.is_superuser:
        agents_to_update = Agent.objects.all()
    elif user.role == CustomUser.ADMIN:
        agents_to_update = Agent.objects.filter(user__company_admin=user)
    else:
        agents_to_update = Agent.objects.filter(user=user)
    
    if not agents_to_update.exists():
        return Response({"error": "No agents found to update."}, status=status.HTTP_404_NOT_FOUND)
    
    config_data = request.data
    valid_keys = ['capture_interval', 'activity_monitoring_enabled', 'network_monitoring_enabled', 'schedule']
    filtered_config = {k: v for k, v in config_data.items() if k in valid_keys}
    
    if not filtered_config:
        return Response({"error": "No valid configuration keys provided."}, status=status.HTTP_400_BAD_REQUEST)
    
    channel_layer = get_channel_layer()
    
    def format_time(t): return t.strftime('%H:%M') if t else None
    schedule_days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]

    with transaction.atomic():
        for agent in agents_to_update:
            if 'capture_interval' in filtered_config:
                agent.capture_interval_seconds = int(filtered_config['capture_interval'])
            if 'activity_monitoring_enabled' in filtered_config:
                agent.is_activity_monitoring_enabled = bool(filtered_config['activity_monitoring_enabled'])
            if 'network_monitoring_enabled' in filtered_config:
                agent.is_network_monitoring_enabled = bool(filtered_config['network_monitoring_enabled'])
            agent.save()
            
            schedule = {day: {"start": format_time(getattr(agent, f'{day}_active_start', None)), "end": format_time(getattr(agent, f'{day}_active_end', None))} for day in schedule_days}

            broadcast_message = {
                "type": "control_command",
                "action": "set_global_config",
                "feature_bundle": "global_config",
                "capture_interval": agent.capture_interval_seconds,
                "activity_monitoring_enabled": agent.is_activity_monitoring_enabled,
                "network_monitoring_enabled": agent.is_network_monitoring_enabled,
                "schedule": schedule
            }
            async_to_sync(channel_layer.group_send)(f"agent_{agent.agent_id}", broadcast_message)
    
    return Response({
        "message": f"Configuration updated and broadcast sent to {agents_to_update.count()} agents.",
        "config_sent": filtered_config
    }, status=status.HTTP_200_OK)


# --- The rest of the history/list views are correct and need no changes ---
@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def agent_data_history_api_view(request):
    # ... (code is sound, no changes needed)
    user = request.user; allowed_agent_ids = []
    if user.is_superuser:
        allowed_agent_ids = list(Agent.objects.values_list('agent_id', flat=True))
    elif user.role == CustomUser.ADMIN:
        allowed_agent_ids = list(Agent.objects.filter(user__company_admin=user).values_list('agent_id', flat=True))
    
    if not allowed_agent_ids: return Response([])
    
    queryset = AgentData.objects.filter(agent_id__in=allowed_agent_ids)
    if agent_id_filter := request.GET.get('agent_id'):
        if agent_id_filter not in allowed_agent_ids: return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        queryset = queryset.filter(agent_id=agent_id_filter)
    if start_time_str := request.GET.get('start_time'): queryset = queryset.filter(timestamp__gte=parse_datetime(start_time_str))
    if end_time_str := request.GET.get('end_time'): queryset = queryset.filter(timestamp__lte=parse_datetime(end_time_str))
    
    limit = int(request.GET.get('limit', 500)); queryset = queryset.order_by('-timestamp')[:limit]
    
    data = [{
        'agent_id': item.agent_id, 
        'timestamp': item.timestamp.isoformat(), 
        'window_title': item.window_title, 
        'active_browser_url': item.active_browser_url, 
        'screenshot_url': request.build_absolute_uri(item.screenshot.url) if item.screenshot else None, 
        'keystroke_count': item.keystroke_count, 
        'mouse_event_count': item.mouse_event_count, 
        'upload_bytes': item.upload_bytes,
        'download_bytes': item.download_bytes,
        'network_type': item.network_type,
        'productive_status': item.productive_status,
        'is_activity_monitoring_enabled': item.is_activity_monitoring_enabled,
        'is_network_monitoring_enabled': item.is_network_monitoring_enabled,
        'capture_interval_seconds': item.capture_interval_seconds
    } for item in queryset]
    return Response(data)

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def recorded_video_list_api_view(request):
    # ... (code is sound, no changes needed)
    user = request.user; queryset = RecordedVideo.objects.none()
    if user.is_superuser:
        queryset = RecordedVideo.objects.select_related('agent__user')
    elif user.role == CustomUser.ADMIN:
        queryset = RecordedVideo.objects.select_related('agent__user').filter(agent__user__company_admin=user)
    
    if agent_id := request.GET.get('agent_id'): queryset = queryset.filter(agent__agent_id=agent_id)
    limit = int(request.GET.get('limit', 50)); queryset = queryset.order_by('-upload_time')[:limit]
    
    data = [{'id': video.id, 'agent_id': video.agent.agent_id, 'user_email': video.agent.user.email, 'filename': video.filename, 'video_url': request.build_absolute_uri(video.video_file.url) if video.video_file else 'Local Storage', 'upload_time': video.upload_time.isoformat(), 'storage_type': 'Local' if not video.video_file else 'Server'} for video in queryset]
    return Response(data)

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def keylog_history_api_view(request):
    # ... (code is sound, no changes needed)
    user = request.user
    allowed_agents = Agent.objects.none()
    if user.is_superuser:
        allowed_agents = Agent.objects.all()
    elif user.role == CustomUser.ADMIN:
        allowed_agents = Agent.objects.filter(user__company_admin=user)
    
    if not allowed_agents.exists(): return Response([])

    queryset = KeyLog.objects.filter(agent__in=allowed_agents)
    if agent_id_filter := request.GET.get('agent_id'):
        if not allowed_agents.filter(agent_id=agent_id_filter).exists(): return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        queryset = queryset.filter(agent__agent_id=agent_id_filter)
        
    log_type = request.GET.get('log_type', 'all')
    if log_type == 'messaging': queryset = queryset.filter(is_messaging_log=True)
    elif log_type == 'general': queryset = queryset.filter(is_messaging_log=False)
        
    limit = int(request.GET.get('limit', 1000)); queryset = queryset.select_related('agent__user').order_by('-timestamp')[:limit]
    
    data = [{'agent_id': log.agent.agent_id, 'user_email': log.agent.user.email, 'timestamp': log.timestamp.isoformat(), 'source_app': log.source_app, 'key_sequence': log.key_sequence, 'is_messaging': log.is_messaging_log} for log in queryset]
    return Response(data)