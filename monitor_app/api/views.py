# monitor_app/api/views.py
import logging
from django.db.models import Subquery, OuterRef
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_datetime, parse_time
from django.utils import timezone
from django.db import transaction
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_http_methods
from accounts.decorators import admin_required
from monitor_app.models import Agent
import json

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.parsers import MultiPartParser, FormParser
import logging

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from ..models import Agent, AgentData, RecordedVideo, KeyLog
from accounts.models import CustomUser
from ..authentication import AgentAPIKeyAuthentication
from ..permissions import AgentPermission


# ==============================================================================
#  AGENT-FACING API Endpoints (Used by the desktop agent)
# ==============================================================================

@api_view(['GET'])
@authentication_classes([AgentAPIKeyAuthentication])
@permission_classes([AgentPermission])
def get_config_api(request):
    """
    Called by agents to get their configuration.
    """
    import logging
    logger = logging.getLogger(__name__)

    # Get agent_id from request headers (set by authentication)
    agent_id = getattr(request, 'agent_id', None)
    logger.info(f"Config request - Agent ID: {agent_id}")
    logger.info(f"Request headers: {dict(request.META)}")

    if not agent_id:
        logger.error("Missing X-AGENT-ID header in config request")
        return Response({
            "error": "Agent ID header (X-AGENT-ID) is required",
            "received_headers": {k: v for k, v in request.META.items() if k.startswith('HTTP_')}
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        agent = Agent.objects.get(agent_id=agent_id)
        logger.info(f"Found agent: {agent}")
    except Agent.DoesNotExist:
        logger.error(f"Agent not found: {agent_id}")
        return Response({"error": f"Agent {agent_id} not found"}, status=status.HTTP_404_NOT_FOUND)

    # FIX: Perform schedule formatting directly in the view
    def format_time(t): return t.strftime('%H:%M') if t else None
    schedule_days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
    schedule = {day: {"start": format_time(getattr(agent, f'{day}_active_start', None)), "end": format_time(getattr(agent, f'{day}_active_end', None))} for day in schedule_days}

    config = {
        "agent_id": agent.agent_id,
        "capture_interval": agent.capture_interval_seconds,
        "activity_monitoring_enabled": agent.is_activity_monitoring_enabled,
        "network_monitoring_enabled": agent.is_network_monitoring_enabled,
        "live_streaming_enabled": agent.is_live_streaming_enabled,
        "keystroke_logging_enabled": agent.is_keystroke_logging_enabled,
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
            logger.error(f"Recording upload error: {str(e)}", exc_info=True)
            return Response({"error": f"Server error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def live_stream_status_api_view(request):
    """
    Returns the live streaming status of all agents for admin dashboard
    """
    user = request.user
    queryset = Agent.objects.none()

    if user.is_superuser or user.role == CustomUser.SUPERADMIN:
        queryset = Agent.objects.select_related('user')
    elif user.role == CustomUser.ADMIN:
        queryset = Agent.objects.select_related('user').filter(user__company_admin=user)

    # Filter for agents that are currently live streaming
    if request.GET.get('live_only') == 'true':
        queryset = queryset.filter(is_live_streaming=True)

    data = []
    for agent in queryset:
        data.append({
            'agent_id': agent.agent_id,
            'user_email': agent.user.email if agent.user else 'Unassigned',
            'is_live_streaming': agent.is_live_streaming,
            'live_stream_url': agent.live_stream_url,
            'is_recording': agent.is_recording,
            'last_seen': agent.last_seen.isoformat(),
        })

    return Response(data)


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
    import logging
    logger = logging.getLogger(__name__)

    # Debug authentication
    logger.info(f"Agent status request - User: {request.user}, Authenticated: {request.user.is_authenticated}")
    logger.info(f"Authorization header: {request.META.get('HTTP_AUTHORIZATION', 'Not present')}")

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
            "is_live_streaming_enabled": agent.is_live_streaming_enabled,
            "is_keystroke_logging_enabled": agent.is_keystroke_logging_enabled,
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
    agent.is_live_streaming_enabled = data.get('live_streaming_enabled', agent.is_live_streaming_enabled)
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
        "live_streaming_enabled": agent.is_live_streaming_enabled,
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

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def live_streams_api_view(request):
    """
    Get all currently live streaming agents
    """
    user = request.user
    live_only = request.GET.get('live_only', 'false').lower() == 'true'

    try:
        # Get agents based on user role
        if user.role == CustomUser.SUPERADMIN:
            agents = Agent.objects.all()
        elif user.role == CustomUser.ADMIN:
            agents = Agent.objects.filter(user__company_admin=user)
        else:
            return Response({"error": "Insufficient permissions"}, status=status.HTTP_403_FORBIDDEN)

        # Filter for live streaming agents if requested
        if live_only:
            agents = agents.filter(is_live_streaming=True, is_live_streaming_enabled=True)

        agents_data = []
        for agent in agents:
            if agent.user:
                agents_data.append({
                    'agent_id': agent.agent_id,
                    'user_email': agent.user.email,
                    'is_live_streaming': agent.is_live_streaming,
                    'is_live_streaming_enabled': agent.is_live_streaming_enabled,
                    'last_seen': agent.last_seen.isoformat() if agent.last_seen else None,
                    'live_stream_url': agent.live_stream_url
                })

        return Response(agents_data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error getting live streams: {e}")
        return Response({"error": "Failed to get live streams"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def toggle_live_streaming_api_view(request, agent_id):
    """
    Toggle live streaming for a specific agent
    """
    user = request.user

    try:
        # Get agent based on user role
        if user.role == CustomUser.SUPERADMIN:
            agent = Agent.objects.get(agent_id=agent_id)
        elif user.role == CustomUser.ADMIN:
            agent = Agent.objects.get(agent_id=agent_id, user__company_admin=user)
        else:
            return Response({"error": "Insufficient permissions"}, status=status.HTTP_403_FORBIDDEN)

        # Toggle live streaming enabled status
        agent.is_live_streaming_enabled = not agent.is_live_streaming_enabled
        agent.save(update_fields=['is_live_streaming_enabled'])

        # Send control command to agent
        channel_layer = get_channel_layer()
        control_message = {
            "type": "control_command",
            "action": "set_global_config",
            "feature_bundle": "global_config",
            "live_streaming_enabled": agent.is_live_streaming_enabled,
            "capture_interval": agent.capture_interval_seconds,
            "activity_monitoring_enabled": agent.is_activity_monitoring_enabled,
            "network_monitoring_enabled": agent.is_network_monitoring_enabled
        }

        async_to_sync(channel_layer.group_send)(f"agent_{agent_id}", control_message)

        return Response({
            "message": f"Live streaming {'enabled' if agent.is_live_streaming_enabled else 'disabled'} for agent {agent_id}",
            "is_live_streaming_enabled": agent.is_live_streaming_enabled
        }, status=status.HTTP_200_OK)

    except Agent.DoesNotExist:
        return Response({"error": "Agent not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error toggling live streaming for agent {agent_id}: {e}")
        return Response({"error": "Failed to toggle live streaming"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def get_agent_config(request):
    """
    Returns the current configuration for the authenticated agent.
    This includes monitoring settings, schedules, and break information.
    """
    try:
        # Get the agent first
        agent_id = request.META.get('HTTP_X_AGENT_ID')
        if not agent_id:
            return Response({'error': 'Agent ID header required'}, status=status.HTTP_400_BAD_REQUEST)

        agent = Agent.objects.get(agent_id=agent_id)
        user = agent.user
        import logging
        logger = logging.getLogger(__name__)

        # Build the schedule object from agent model
        schedule = {}
        for day in ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']:
            start_field = f'{day}_active_start'
            end_field = f'{day}_active_end'
            start_time = getattr(agent, start_field)
            end_time = getattr(agent, end_field)

            schedule[day] = {
                'start': start_time.strftime('%H:%M') if start_time else None,
                'end': end_time.strftime('%H:%M') if end_time else None
            }

        # Get break schedules for the user
        company_breaks = []
        user_break_schedule = []
        is_user_on_leave = False

        if user and user.company_admin:
            # Get company-wide breaks
            from accounts.models import CompanyBreakSchedule
            company_break_schedules = CompanyBreakSchedule.objects.filter(
                admin=user.company_admin,
                is_active=True
            )

            company_breaks = [
                {
                    'name': schedule.name,
                    'day': schedule.day,
                    'start': schedule.start_time.strftime('%H:%M'),
                    'end': schedule.end_time.strftime('%H:%M')
                }
                for schedule in company_break_schedules
            ]

            # Get user-specific breaks
            from accounts.models import UserBreakSchedule
            user_break_schedules = UserBreakSchedule.objects.filter(
                user=user,
                is_active=True
            )

            for schedule in user_break_schedules:
                if schedule.is_on_leave:
                    is_user_on_leave = True
                elif schedule.start_time and schedule.end_time:  # Only add if both times are set
                    user_break_schedule.append({
                        'name': schedule.name,
                        'day': schedule.day,
                        'start': schedule.start_time.strftime('%H:%M'),
                        'end': schedule.end_time.strftime('%H:%M')
                    })

            # Log the break schedules being sent
            logger.info(f"Sending break schedules to agent {agent_id}:")
            logger.info(f"  Company breaks: {len(company_breaks)} schedules")
            logger.info(f"  User breaks: {len(user_break_schedule)} schedules") 
            logger.info(f"  User on leave: {is_user_on_leave}")

        # Return agent-specific configuration
        config = {
            'agent_config': {
                'capture_interval_seconds': agent.capture_interval_seconds,
                'is_activity_monitoring_enabled': agent.is_activity_monitoring_enabled,
                'is_network_monitoring_enabled': agent.is_network_monitoring_enabled,
                'is_live_streaming_enabled': agent.is_live_streaming_enabled,
                'is_keystroke_logging_enabled': getattr(agent, 'is_keystroke_logging_enabled', False),
                'schedule': schedule
            },
            'company_breaks': company_breaks,
            'user_break_schedule': user_break_schedule,
            'is_user_on_leave': is_user_on_leave
        }

        return Response(config, status=status.HTTP_200_OK)

    except Agent.DoesNotExist:
        return Response({'error': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': f'Configuration fetch failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVERERROR)

@login_required
@admin_required
def agent_status_api(request):
    """
    API endpoint to get agent status for the admin's managed users.
    """
    try:
        # Get agents for users managed by this admin
        from accounts.models import CustomUser
        managed_users = CustomUser.objects.filter(
            company_admin=request.user,             role=CustomUser.USER
        )

        agents_data = []
        for user in managed_users:
            for agent in user.agents.all():
                agents_data.append({
                    'agent_id': agent.agent_id,
                    'user_name': user.get_full_name(),
                    'user_email': user.email,
                    'is_online': agent.is_active,
                    'is_monitoring_active': agent.is_active,
                    'last_seen': agent.last_seen.strftime('%Y-%m-%d %H:%M:%S') if agent.last_seen else None,
                })

        return JsonResponse({
            'success': True,
            'agents': agents_data
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        })

@login_required
@admin_required
@csrf_exempt
@require_http_methods(["POST"])
def admin_control_agents_api(request):
    """
    API endpoint for admin to control agents.
    """
    try:
        data = json.loads(request.body)
        action = data.get('action')
        agent_id = data.get('agent_id')

        if action == 'resume_all':
            # Resume all agents for managed users
            from accounts.models import CustomUser
            managed_users = CustomUser.objects.filter(
                company_admin=request.user, 
                role=CustomUser.USER
            )

            count = 0
            for user in managed_users:
                for agent in user.agents.all():
                    agent.is_active = True
                    agent.save()
                    count += 1

            return JsonResponse({
                'success': True,
                'message': f'Resumed {count} agents'
            })

        elif action == 'toggle' and agent_id:
            # Toggle specific agent
            try:
                agent = Agent.objects.get(
                    agent_id=agent_id,
                    user__company_admin=request.user
                )
                agent.is_active = not agent.is_active
                agent.save()

                return JsonResponse({
                    'success': True,
                    'message': f'Agent {agent_id} {"activated" if agent.is_active else "deactivated"}'
                })
            except Agent.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'message': 'Agent not found'
                })

        else:
            return JsonResponse({
                'success': False,
                'message': 'Invalid action'
            })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        })


@api_view(['POST'])
@authentication_classes([AgentAPIKeyAuthentication])
@permission_classes([])
def receive_heartbeat(request):
    """
    Receives heartbeat data from agents and updates their status.
    """
    import logging
    logger = logging.getLogger(__name__)

    try:
        agent_id = getattr(request, 'agent_id', None)
        if not agent_id:
            return Response({"error": "Agent ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        data = request.data
        logger.debug(f"Received heartbeat from agent {agent_id}")

        # Check if agent is on break or outside schedule
        is_on_break = data.get('is_on_break', False)
        is_agent_active_by_schedule = data.get('is_agent_active_by_schedule', True)

        if is_on_break or not is_agent_active_by_schedule:
            logger.info(f"Agent {agent_id} on break/outside schedule - skipping database save")

            # Only update basic agent status, don't save to AgentData
            try:
                agent = Agent.objects.get(agent_id=agent_id)
                agent.productive_status = data.get('productive_status', 'On Break')
                agent.is_recording = False  # Force recording off during breaks
                agent.is_live_streaming = False  # Force streaming off during breaks
                agent.save(update_fields=['productive_status', 'is_recording', 'is_live_streaming', 'last_seen'])

                return Response({"status": "break_mode", "message": "Agent on break - no data saved"}, status=status.HTTP_200_OK)

            except Agent.DoesNotExist:
                return Response({"error": "Agent not found"}, status=status.HTTP_404_NOT_FOUND)

        # Normal processing when not on break
        # Get or create agent
        try:
            agent = Agent.objects.get(agent_id=agent_id)
        except Agent.DoesNotExist:
            logger.error(f"Agent {agent_id} not found")
            return Response({"error": "Agent not found"}, status=status.HTTP_404_NOT_FOUND)

        # Update agent status
        agent.last_seen = timezone.now()
        agent.window_title = data.get('window_title', '')
        agent.active_browser_url = data.get('active_browser_url', '')
        agent.is_recording = data.get('is_recording', False)
        agent.save()

        # Create AgentData entry if screenshot or activity data is present
        if data.get('screenshot') or data.get('keystroke_count', 0) > 0:
            agent_data = AgentData.objects.create(
                agent_id=agent_id,
                window_title=data.get('window_title', ''),
                active_browser_url=data.get('active_browser_url', ''),
                keystroke_count=data.get('keystroke_count', 0),
                mouse_event_count=data.get('mouse_event_count', 0),
                upload_bytes=data.get('upload_bytes', 0),
                download_bytes=data.get('download_bytes', 0),
                network_type=data.get('network_type', ''),
                productive_status=data.get('productive_status', 'unknown'),
                is_activity_monitoring_enabled=data.get('is_activity_monitoring_enabled', True),
                is_network_monitoring_enabled=data.get('is_network_monitoring_enabled', True),
                capture_interval_seconds=data.get('current_interval_seconds', 30)
            )

            # Handle screenshot if present
            if data.get('screenshot'):
                import base64
                from django.core.files.base import ContentFile
                try:
                    screenshot_data = base64.b64decode(data['screenshot'])
                    screenshot_file = ContentFile(screenshot_data, name=f'screenshot_{agent_id}_{timezone.now().strftime("%Y%m%d_%H%M%S")}.png')
                    agent_data.screenshot.save(screenshot_file.name, screenshot_file)
                except Exception as e:
                    logger.error(f"Error saving screenshot: {e}")

        return Response({"status": "success"}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error processing heartbeat: {e}")
        return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@authentication_classes([AgentAPIKeyAuthentication])
@permission_classes([])
def upload_recording(request):
    """
    Handles video recording uploads from agents.
    """
    return RecordingUploadAPIView().post(request)


@api_view(['POST'])
@authentication_classes([AgentAPIKeyAuthentication])
@permission_classes([])
def receive_keylog(request):
    """
    Receives keystroke log data from agents.
    """
    import logging
    logger = logging.getLogger(__name__)

    try:
        agent_id = getattr(request, 'agent_id', None)
        if not agent_id:
            return Response({"error": "Agent ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        data = request.data

        # Get agent
        try:
            agent = Agent.objects.get(agent_id=agent_id)
        except Agent.DoesNotExist:
            return Response({"error": "Agent not found"}, status=status.HTTP_404_NOT_FOUND)

        # Create keylog entry
        KeyLog.objects.create(
            agent=agent,
            source_app=data.get('source_app', 'Unknown'),
            key_sequence=data.get('key_sequence', ''),
            is_messaging_log=data.get('is_messaging', False)
        )

        return Response({"status": "success"}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error processing keylog: {e}")
        return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def test_auth(request):
    """
    Simple endpoint to test JWT authentication
    """
    return Response({
        "message": "Authentication successful",
        "user": request.user.email,
        "user_id": request.user.id
    })


@api_view(['GET'])
@authentication_classes([AgentAPIKeyAuthentication])
@permission_classes([AgentPermission])
def get_break_schedules(request):
    """
    API endpoint for agents to fetch break schedules for their user.
    """
    try:
        agent = Agent.objects.get(agent_id=request.headers.get('X-AGENT-ID'))
        if not agent.user:
            return Response({"error": "Agent not paired with user"}, status=status.HTTP_400_BAD_REQUEST)

        # Get company break schedules
        company_breaks = []
        if hasattr(agent.user, 'company_admin') and agent.user.company_admin:
            from accounts.models import CompanyBreakSchedule
            company_schedules = CompanyBreakSchedule.objects.filter(
                admin=agent.user.company_admin,
                is_active=True
            )
            for schedule in company_schedules:
                company_breaks.append({
                    'name': schedule.name,
                    'day': schedule.day,
                    'start_time': schedule.start_time.strftime('%H:%M'),
                    'end_time': schedule.end_time.strftime('%H:%M'),
                })

        # Get user-specific break schedules
        user_breaks = []
        from accounts.models import UserBreakSchedule
        user_schedules = UserBreakSchedule.objects.filter(
            user=agent.user,
            is_active=True
        )

        # Check if user is on leave
        is_user_on_leave = user_schedules.filter(is_on_leave=True).exists()

        for schedule in user_schedules:
            if schedule.is_on_leave:
                continue  # Handle leave status separately

            user_breaks.append({
                'name': schedule.name,
                'day': schedule.day,
                'start_time': schedule.start_time.strftime('%H:%M') if schedule.start_time else None,
                'end_time': schedule.end_time.strftime('%H:%M') if schedule.end_time else None,
            })

        return Response({
            'company_breaks': company_breaks,
            'user_break_schedule': user_breaks,
            'is_user_on_leave': is_user_on_leave
        })

    except Agent.DoesNotExist:
        return Response({"error": "Agent not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error fetching break schedules: {e}")
        return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)