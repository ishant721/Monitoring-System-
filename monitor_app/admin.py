# monitor_app/admin.py

from django.contrib import admin
from django.utils.html import format_html
from .models import Agent, AgentData, RecordedVideo, KeyLog

@admin.register(Agent)
class AgentAdmin(admin.ModelAdmin):
    """
    Admin interface for the Agent model. Allows viewing agent status
    and manually editing their configurations.
    """
    list_display = (
        'agent_id',
        'user',  # Display the linked user
        'is_activity_monitoring_enabled',
        'is_recording',
        'last_seen',
    )
    list_filter = ('is_activity_monitoring_enabled', 'is_network_monitoring_enabled', 'is_recording')
    search_fields = ('agent_id', 'user__email', 'window_title')
    readonly_fields = ('last_seen',)

    fieldsets = (
        ('Agent Identity', {
            'fields': ('agent_id', 'user')
        }),
        ('Live Status (Read-Only)', {
            'fields': ('last_seen', 'window_title', 'active_browser_url', 'is_recording', 'productive_status')
        }),
        ('Monitoring Configuration', {
            'fields': ('is_activity_monitoring_enabled', 'is_network_monitoring_enabled', 'capture_interval_seconds')
        }),
        ('Daily Monitoring Schedule (UTC Time)', {
            'classes': ('collapse',), # Make this section collapsible
            'fields': (
                ('monday_active_start', 'monday_active_end'),
                ('tuesday_active_start', 'tuesday_active_end'),
                ('wednesday_active_start', 'wednesday_active_end'),
                ('thursday_active_start', 'thursday_active_end'),
                ('friday_active_start', 'friday_active_end'),
                ('saturday_active_start', 'saturday_active_end'),
                ('sunday_active_start', 'sunday_active_end'),
            )
        }),
    )

@admin.register(AgentData)
class AgentDataAdmin(admin.ModelAdmin):
    """
    Admin interface for the historical AgentData logs.
    This is primarily for viewing and debugging.
    """
    list_display = ('agent_id', 'timestamp', 'window_title', 'productive_status', 'screenshot_thumbnail')
    list_filter = ('agent_id', 'timestamp', 'productive_status')
    search_fields = ('agent_id', 'window_title', 'active_browser_url')
    # Make all fields read-only to prevent accidental data modification
    readonly_fields = [f.name for f in AgentData._meta.get_fields()]

    def screenshot_thumbnail(self, obj):
        if obj.screenshot and hasattr(obj.screenshot, 'url'):
            return format_html(f'<a href="{obj.screenshot.url}" target="_blank"><img src="{obj.screenshot.url}" width="150" /></a>')
        return "No Screenshot"
    screenshot_thumbnail.short_description = "Screenshot"

    def has_add_permission(self, request):
        return False # Data should only come from the agent

    def has_change_permission(self, request, obj=None):
        return False # Data is historical and should not be changed

@admin.register(RecordedVideo)
class RecordedVideoAdmin(admin.ModelAdmin):
    """Admin interface for viewing uploaded screen recordings."""
    list_display = ('agent', 'filename', 'upload_time', 'video_link')
    list_filter = ('agent__user__email', 'upload_time')
    search_fields = ('filename', 'agent__agent_id')
    readonly_fields = ('agent', 'filename', 'video_file', 'upload_time', 'duration_seconds', 'video_link_display')

    def video_link(self, obj):
        if obj.video_file and hasattr(obj.video_file, 'url'):
            return format_html(f'<a href="{obj.video_file.url}" target="_blank">Download/View</a>')
        return "N/A"
    
    def video_link_display(self, obj):
        if obj.video_file and hasattr(obj.video_file, 'url'):
            return format_html(f'<video controls style="max-width: 400px;"><source src="{obj.video_file.url}" type="video/mp4"></video>')
        return "No video file."
    video_link_display.short_description = "Video Playback"

    def has_add_permission(self, request):
        return False

@admin.register(KeyLog)
class KeyLogAdmin(admin.ModelAdmin):
    """Admin interface for viewing captured keystroke logs."""
    list_display = ('agent', 'timestamp', 'source_app', 'is_messaging_log')
    list_filter = ('is_messaging_log', 'agent__user__email', 'timestamp')
    search_fields = ('key_sequence', 'source_app', 'agent__agent_id')
    readonly_fields = [f.name for f in KeyLog._meta.get_fields()]

    def has_add_permission(self, request):
        return False
        
    def has_change_permission(self, request, obj=None):
        return False