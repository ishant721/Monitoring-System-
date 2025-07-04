# Generated by Django 5.2.3 on 2025-06-30 08:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('monitor_app', '0008_agent_is_video_recording_enabled'),
    ]

    operations = [
        migrations.AddField(
            model_name='agent',
            name='is_screenshot_capturing_enabled',
            field=models.BooleanField(default=True, help_text='Whether screenshot capturing is enabled for this agent'),
        ),
    ]
