# monitor_app/models.py

from django.db import models
from django.conf import settings
from django.utils import timezone
import os

# ==============================================================================
#  HELPER FUNCTIONS
# ==============================================================================

def screenshot_upload_path(instance, filename):
    """
    Generates a structured path for uploaded screenshots to keep them organized.
    Example: MEDIA_ROOT/screenshots/agent_id/YYYY/MM/DD/timestamp_filename.png
    """
    agent_id = instance.agent_id or 'unknown_agent'
    now = instance.timestamp or timezone.now()
    return os.path.join(
        'screenshots',
        agent_id,
        str(now.year),
        f'{now.month:02d}', # Padded month
        f'{now.day:02d}',  # Padded day
        f'{now.strftime("%H%M%S%f")}_{filename}'
    )

def video_upload_path(instance, filename):
    """
    Generates a structured path for uploaded video recordings.
    """
    agent_id = instance.agent.agent_id if instance.agent else 'unknown_agent'
    now = timezone.now()
    return os.path.join(
        'recordings',
        agent_id,
        str(now.year),
        f'{now.month:02d}',
        f'{now.day:02d}',
        filename
    )

# ==============================================================================
#  CORE MODELS
# ==============================================================================

class Agent(models.Model):
    """
    Represents a single monitoring agent instance.
    This model stores the agent's unique ID, its current live status,
    and its specific configuration settings.
    """
    # --- The crucial link to your user system ---
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="agents",
        null=True, # Allows agent to exist before being paired
        blank=True
    )
    
    agent_id = models.CharField(max_length=255, unique=True, db_index=True)
    last_seen = models.DateTimeField(auto_now=True)

    # --- Live Status Fields (updated by heartbeat) ---
    window_title = models.CharField(max_length=512, blank=True, null=True)
    active_browser_url = models.URLField(max_length=2048, blank=True, null=True)
    is_recording = models.BooleanField(default=False)
    productive_status = models.CharField(max_length=50, default="N/A")

    # --- Per-Agent Configuration Fields ---
    capture_interval_seconds = models.IntegerField(default=10)
    is_activity_monitoring_enabled = models.BooleanField(default=True)
    is_network_monitoring_enabled = models.BooleanField(default=True)
    
    # Per-Agent Daily Schedule
    monday_active_start = models.TimeField(null=True, blank=True); monday_active_end = models.TimeField(null=True, blank=True)
    tuesday_active_start = models.TimeField(null=True, blank=True); tuesday_active_end = models.TimeField(null=True, blank=True)
    wednesday_active_start = models.TimeField(null=True, blank=True); wednesday_active_end = models.TimeField(null=True, blank=True)
    thursday_active_start = models.TimeField(null=True, blank=True); thursday_active_end = models.TimeField(null=True, blank=True)
    friday_active_start = models.TimeField(null=True, blank=True); friday_active_end = models.TimeField(null=True, blank=True)
    saturday_active_start = models.TimeField(null=True, blank=True); saturday_active_end = models.TimeField(null=True, blank=True)
    sunday_active_start = models.TimeField(null=True, blank=True); sunday_active_end = models.TimeField(null=True, blank=True)

    def __str__(self):
        return f"Agent ({self.agent_id[:8]}...) for {self.user.email if self.user else 'Unassigned'}"

class AgentData(models.Model):
    """
    Stores a historical log of a single heartbeat from an agent.
    This is used for the 'Historical Data' table.
    """
    agent_id = models.CharField(max_length=255, db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    window_title = models.CharField(max_length=512, blank=True, null=True)
    active_browser_url = models.CharField(max_length=2048, blank=True, null=True)
    screenshot = models.ImageField(upload_to=screenshot_upload_path, blank=True, null=True)
    keystroke_count = models.BigIntegerField(default=0)
    mouse_event_count = models.BigIntegerField(default=0)
    upload_bytes = models.BigIntegerField(default=0)
    download_bytes = models.BigIntegerField(default=0)
    network_type = models.CharField(max_length=255, blank=True, null=True)
    productive_status = models.CharField(max_length=50, default="N/A")
    # Store config state at the time of capture
    is_activity_monitoring_enabled = models.BooleanField(default=True)
    is_network_monitoring_enabled = models.BooleanField(default=True)
    capture_interval_seconds = models.IntegerField(default=10)

    class Meta:
        ordering = ['-timestamp']

class RecordedVideo(models.Model):
    """Stores metadata and a file path for an uploaded screen recording."""
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='recorded_videos')
    filename = models.CharField(max_length=255)
    video_file = models.FileField(upload_to=video_upload_path)
    upload_time = models.DateTimeField(auto_now_add=True)
    duration_seconds = models.IntegerField(blank=True, null=True)

    class Meta:
        ordering = ['-upload_time']
        verbose_name_plural = 'Recorded Videos'

# monitor_app/models.py
from django.db import models
from django.conf import settings

# ... (Agent, AgentData, RecordedVideo models are correct) ...

class KeyLog(models.Model):
    """
    Stores a log of a user's typing activity from a specific application.
    """
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='keylogs')
    timestamp = models.DateTimeField(auto_now_add=True)
    
    source_app = models.CharField(max_length=255, help_text="The application or website where typing occurred.")
    key_sequence = models.TextField(help_text="The captured sequence of keystrokes.")
    
    # This flag is set by the agent to categorize the log type.
    is_messaging_log = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Keystroke Log"
        verbose_name_plural = "Keystroke Logs"

    def __str__(self):
        return f"Log from {self.source_app} at {self.timestamp}"