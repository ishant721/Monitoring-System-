
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, Group, Permission
from django.utils import timezone
from datetime import timedelta, date
from django.conf import settings # For settings like OTP_VALIDITY_MINUTES

import logging
logger = logging.getLogger(__name__)


class CompanyBreakSchedule(models.Model):
    """
    Defines company-wide break schedules that apply to all employees.
    """
    admin = models.ForeignKey(
        'CustomUser', 
        on_delete=models.CASCADE, 
        related_name='company_break_schedules',
        limit_choices_to={'role': 'ADMIN'}
    )
    name = models.CharField(max_length=100, help_text="Break name (e.g., 'Lunch Break', 'Coffee Break')")
    
    WEEKDAY_CHOICES = [
        ('monday', 'Monday'),
        ('tuesday', 'Tuesday'),
        ('wednesday', 'Wednesday'),
        ('thursday', 'Thursday'),
        ('friday', 'Friday'),
        ('saturday', 'Saturday'),
        ('sunday', 'Sunday'),
        ('daily', 'Every Day'),
    ]
    
    day = models.CharField(max_length=10, choices=WEEKDAY_CHOICES, default='daily')
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Company Break Schedule"
        verbose_name_plural = "Company Break Schedules"
        ordering = ['day', 'start_time']
    
    def __str__(self):
        return f"{self.name} - {self.get_day_display()} ({self.start_time}-{self.end_time})"


class UserBreakSchedule(models.Model):
    """
    Defines user-specific break schedules and leave status.
    """
    user = models.ForeignKey(
        'CustomUser', 
        on_delete=models.CASCADE, 
        related_name='user_break_schedules',
        limit_choices_to={'role': 'USER'}
    )
    name = models.CharField(max_length=100, help_text="Break name (e.g., 'Personal Break', 'Medical Appointment')")
    
    WEEKDAY_CHOICES = [
        ('monday', 'Monday'),
        ('tuesday', 'Tuesday'),
        ('wednesday', 'Wednesday'),
        ('thursday', 'Thursday'),
        ('friday', 'Friday'),
        ('saturday', 'Saturday'),
        ('sunday', 'Sunday'),
        ('daily', 'Every Day'),
    ]
    
    day = models.CharField(max_length=10, choices=WEEKDAY_CHOICES, default='daily')
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    
    # For extended leave periods
    is_on_leave = models.BooleanField(default=False, help_text="User is on extended leave")
    leave_start_date = models.DateField(null=True, blank=True)
    leave_end_date = models.DateField(null=True, blank=True)
    leave_reason = models.TextField(blank=True, null=True)
    
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "User Break Schedule"
        verbose_name_plural = "User Break Schedules"
        ordering = ['day', 'start_time']
    
    def __str__(self):
        if self.is_on_leave:
            return f"{self.user.email} - On Leave ({self.leave_start_date} to {self.leave_end_date})"
        return f"{self.user.email} - {self.name} - {self.get_day_display()} ({self.start_time}-{self.end_time})"


class AdminFeatureRestrictions(models.Model):
    """
    Controls which features are available to each admin company based on their subscription level.
    This is managed by superadmins to implement subscription-based feature restrictions.
    """
    admin = models.OneToOneField(
        'CustomUser', 
        on_delete=models.CASCADE, 
        related_name='feature_restrictions',
        limit_choices_to={'role': 'ADMIN'}
    )
    
    # Core monitoring features
    can_use_activity_monitoring = models.BooleanField(default=True, help_text="Allow basic activity tracking")
    can_use_network_monitoring = models.BooleanField(default=True, help_text="Allow network usage monitoring")
    can_use_screenshot_capturing = models.BooleanField(default=True, help_text="Allow screenshot capture")
    
    # Advanced monitoring features (typically premium)
    can_use_live_streaming = models.BooleanField(default=False, help_text="Allow live screen streaming")
    can_use_video_recording = models.BooleanField(default=False, help_text="Allow video recording")
    can_use_keystroke_logging = models.BooleanField(default=False, help_text="Allow keystroke logging")
    can_use_email_monitoring = models.BooleanField(default=False, help_text="Allow email monitoring")
    
    # Administrative features
    can_configure_monitoring = models.BooleanField(default=True, help_text="Allow configuring monitoring settings")
    can_manage_email_config = models.BooleanField(default=True, help_text="Allow email server configuration")
    
    # Feature limits
    max_screenshot_retention_days = models.IntegerField(default=30, help_text="Maximum days to retain screenshots")
    max_video_retention_days = models.IntegerField(default=7, help_text="Maximum days to retain videos")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Admin Feature Restriction"
        verbose_name_plural = "Admin Feature Restrictions"
    
    def __str__(self):
        return f"Feature restrictions for {self.admin.email}"
    
    @classmethod
    def get_or_create_for_admin(cls, admin_user):
        """Get or create feature restrictions for an admin with default settings"""
        restrictions, created = cls.objects.get_or_create(
            admin=admin_user,
            defaults={
                'can_use_activity_monitoring': True,
                'can_use_network_monitoring': True,
                'can_use_screenshot_capturing': True,
                'can_use_live_streaming': False,
                'can_use_video_recording': False,
                'can_use_keystroke_logging': False,
                'can_use_email_monitoring': False,
                'can_configure_monitoring': True,
                'can_manage_email_config': True,
            }
        )
        return restrictions



# accounts/models.py
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, Group, Permission
from django.utils import timezone
from datetime import timedelta, date
from django.conf import settings # For settings like OTP_VALIDITY_MINUTES

import logging
logger = logging.getLogger(__name__)


class CustomUserManager(BaseUserManager):
    def get_by_natural_key(self, email):
        """
        Allows login using case-insensitive email.
        """
        return self.get(email__iexact=email.lower())

    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a CustomUser with the given email and password.
        """
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email).lower() # Normalize email to lowercase
        
        # Remove fields that might be managed internally or not applicable at base creation
        extra_fields.pop('is_phone_verified', None) 
        extra_fields.pop('phone_otp', None)        
        
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True) 
        extra_fields.setdefault('role', CustomUser.SUPERADMIN) 
        extra_fields.setdefault('is_email_verified', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        if extra_fields.get('role') != CustomUser.SUPERADMIN:
            raise ValueError('Superuser must have role set to SUPERADMIN.')

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractUser):
    USER = 'USER'
    ADMIN = 'ADMIN'
    SUPERADMIN = 'SUPERADMIN'
    ROLE_CHOICES = [
        (USER, 'User (Employee)'),
        (ADMIN, 'Admin (Company)'),
        (SUPERADMIN, 'Superadmin'),
    ]

    class AdminAccountType(models.TextChoices):
        NONE = 'NONE', 'Not Set' 
        TRIAL = 'TRIAL', 'Trial Account'
        SUBSCRIBED = 'SUBSCRIBED', 'Subscribed Account'
        EXPIRED = 'EXPIRED', 'Expired/Locked'
    
    agent_pairing_token = models.UUIDField(null=True, blank=True, unique=True)
    agent_pairing_token_expires = models.DateTimeField(null=True, blank=True)


    username = None 
    email = models.EmailField(unique=True, help_text="Primary email address, used for login.")
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default=USER)
    phone_number = models.CharField(max_length=17, null=True, blank=True, help_text="Optional phone number, e.g., +12223334444")
    
    is_email_verified = models.BooleanField(default=False)
    email_otp = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=False, help_text="Overall account active status. Admins also need active access type and approval.")

    approved_by = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='approved_entities', help_text="User who approved this account's activation."
    )
    company_admin = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='company_employees', limit_choices_to={'role': ADMIN},
        help_text="For USER role, links to their Company Admin."
    )
    
    max_allowed_users = models.PositiveIntegerField(
        null=True, blank=True, default=0, 
        help_text="For ADMIN: Max active users they can manage. Set to 0 if their access expires."
    )
    admin_account_type = models.CharField(
        max_length=20, choices=AdminAccountType.choices, default=AdminAccountType.NONE,
        help_text="Type of account for Admins (e.g., Trial, Subscribed, Expired)."
    )
    access_granted_by = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='granted_admin_access_set', 
        limit_choices_to={'role': SUPERADMIN},
        help_text="Superadmin who approved or last modified the access period for this Admin."
    )
    access_ends_at = models.DateTimeField(
        null=True, blank=True,
        help_text="When current access (Trial or Subscription) for this Admin ends."
    )
    trial_extension_requested = models.BooleanField(
        default=False, help_text="Flag if ADMIN requested trial extension."
    )
    trial_extension_reason = models.TextField(
        blank=True, null=True, help_text="Reason for ADMIN's trial extension request."
    )

    groups = models.ManyToManyField(
        Group, verbose_name='groups', blank=True,
        help_text='The groups this user belongs to.',
        related_name="customuser_groups_set", related_query_name="customuser_group",
    )
    user_permissions = models.ManyToManyField(
        Permission, verbose_name='user permissions', blank=True,
        help_text='Specific permissions for this user.',
        related_name="customuser_permissions_set", related_query_name="customuser_permission",
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [] 
    objects = CustomUserManager()

    _original_max_allowed_users = None
    _original_admin_account_type = None
    _original_access_ends_at = None

    def generate_agent_pairing_token(self):
        """Generates a new, short-lived token for pairing an agent."""
        self.agent_pairing_token = uuid.uuid4()
        # Token is valid for a short time, e.g., 60 minutes
        self.agent_pairing_token_expires = timezone.now() + timedelta(minutes=10)
        self.save(update_fields=['agent_pairing_token', 'agent_pairing_token_expires'])
        return self.agent_pairing_token

    def is_pairing_token_valid(self, token_to_check):
        """Checks if a provided token matches and has not expired."""
        if not self.agent_pairing_token or not self.agent_pairing_token_expires:
            return False
        
        # Insecure but simple comparison. Use hmac.compare_digest in production.
        return str(token_to_check) == str(self.agent_pairing_token) and timezone.now() < self.agent_pairing_token_expires

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._original_max_allowed_users = self.max_allowed_users
        self._original_admin_account_type = self.admin_account_type
        self._original_access_ends_at = self.access_ends_at

    def __str__(self):
        return self.email

    def get_full_name(self):
        name = f"{self.first_name} {self.last_name}".strip()
        return name if name else self.email

    def is_otp_valid(self):
        otp_validity_minutes = getattr(settings, 'OTP_VALIDITY_MINUTES', 10)
        return bool(self.otp_created_at and timezone.now() < self.otp_created_at + timedelta(minutes=otp_validity_minutes))
    
    def get_current_approved_users_count(self):
        if self.role == self.ADMIN: 
            return CustomUser.objects.filter(company_admin=self, role=self.USER, is_active=True, approved_by__isnull=False).count()
        return 0

    @property
    def is_admin_access_active(self):
        if self.role != self.ADMIN: return True 
        if not self.is_active: return False

        if self.admin_account_type == self.AdminAccountType.SUBSCRIBED:
            return not self.access_ends_at or timezone.now() < self.access_ends_at
        elif self.admin_account_type == self.AdminAccountType.TRIAL:
            return bool(self.access_ends_at and timezone.now() < self.access_ends_at)
        return False

    def can_approve_more_users(self):
        if self.role != self.ADMIN: return True
        if not self.is_admin_access_active: return False
        
        current_max = self.max_allowed_users if self.max_allowed_users is not None else 0
        if current_max == 0: return False
        return self.get_current_approved_users_count() < current_max

    @property
    def access_days_remaining(self):
        if self.role == self.ADMIN and self.access_ends_at and \
           self.admin_account_type in [self.AdminAccountType.TRIAL, self.AdminAccountType.SUBSCRIBED]:
            if self.access_ends_at > timezone.now(): 
                return (self.access_ends_at.date() - timezone.now().date()).days
            return 0 
        return None
    
    # /---------------------------------------------\
    # | --- NEW, NON-INTRUSIVE HELPER METHODS ---   |
    # |  These read-only properties do not change   |
    # |     any fields or require migrations.       |
    # \---------------------------------------------/

    @property
    def is_monitored(self):
        """
        Checks if this user has any monitoring agents assigned.
        This uses the 'agents' related_name from monitor_app.Agent.
        """
        if self.role == self.USER:
            return self.agents.exists()
        return False

    def get_last_activity_timestamp(self):
        """
        Finds the most recent 'last_seen' time from all of this user's agents.
        Returns a datetime object or None.
        """
        if self.role == self.USER and self.is_monitored:
            latest_agent = self.agents.order_by('-last_seen').first()
            return latest_agent.last_seen if latest_agent else None
        return None


    # --- THE APPROVED FUNCTIONALITY BELOW IS UNCHANGED ---

    def _deactivate_managed_users(self, reason="Admin account access change leading to user deactivation"):
        from .utils import send_user_account_status_email # Moved import here
        managed_users_qs = CustomUser.objects.filter(company_admin=self, role=self.USER, is_active=True)
        if managed_users_qs.exists():
            users_to_notify = list(managed_users_qs) 
            updated_count = managed_users_qs.update(is_active=False)
            logger.info(f"{updated_count} users for Admin {self.email} auto-deactivated. Reason: {reason}.")
            
            # Stop monitoring agents for each deactivated user
            self._stop_monitoring_for_users(users_to_notify, reason)
            
            for user_to_notify in users_to_notify:
                send_user_account_status_email(user_to_notify, is_activated=False, by_who=self, reason=f"Associated Admin account ({self.email}) status change: {reason}")
    
    def _stop_monitoring_for_users(self, users_list, reason):
        """
        Stops all monitoring agents and email listeners for a list of users.
        """
        try:
            from monitor_app.models import Agent
            from mail_monitor.models import EmailAccount
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            
            channel_layer = get_channel_layer()
            
            for user in users_list:
                # Stop monitoring agents
                user_agents = Agent.objects.filter(user=user)
                for agent in user_agents:
                    agent.is_activity_monitoring_enabled = False
                    agent.is_network_monitoring_enabled = False
                    agent.is_live_streaming_enabled = False
                    agent.save(update_fields=[
                        'is_activity_monitoring_enabled', 
                        'is_network_monitoring_enabled', 
                        'is_live_streaming_enabled'
                    ])
                    logger.info(f"Disabled monitoring for agent {agent.agent_id} due to admin change: {reason}")
                
                # Stop email monitoring
                try:
                    email_account = EmailAccount.objects.get(user=user)
                    if email_account.is_active or email_account.is_authenticated:
                        email_account.is_active = False
                        email_account.is_authenticated = False
                        email_account.save(update_fields=['is_active', 'is_authenticated'])
                        
                        # Send signal to stop email listener
                        async_to_sync(channel_layer.send)(
                            "email-listener",
                            {"type": "stop.listening", "account_id": email_account.id}
                        )
                        logger.info(f"Stopped email monitoring for user {user.email} due to admin change: {reason}")
                except EmailAccount.DoesNotExist:
                    pass
                except Exception as e:
                    logger.error(f"Failed to stop email monitoring for user {user.email}: {e}")
                    
        except Exception as e:
            logger.error(f"Error stopping monitoring for users during admin deactivation: {e}")
    
    def save(self, *args, **kwargs):
        if self.email: self.email = self.email.lower()

        is_existing_admin_update = bool(self.pk and self.role == self.ADMIN)
        
        # --- Stage 1: Determine Admin's Access State & Enforce Consequences on `self` ---
        if is_existing_admin_update:
            will_be_admin_access_active_after_save = False 
            if self.is_active:
                if self.admin_account_type == self.AdminAccountType.SUBSCRIBED:
                    will_be_admin_access_active_after_save = not self.access_ends_at or timezone.now() < self.access_ends_at
                elif self.admin_account_type == self.AdminAccountType.TRIAL:
                    will_be_admin_access_active_after_save = bool(self.access_ends_at and timezone.now() < self.access_ends_at)
            
            if not will_be_admin_access_active_after_save:
                if self.admin_account_type != self.AdminAccountType.EXPIRED:
                    logger.info(f"Admin {self.email}'s access is ending or type is invalid for active access. Marking as EXPIRED.")
                    self.admin_account_type = self.AdminAccountType.EXPIRED
                
                if self.max_allowed_users != 0:
                    logger.info(f"Admin {self.email}'s access is inactive/expired. Forcing max_allowed_users from {self.max_allowed_users if self.max_allowed_users is not None else 'None'} to 0.")
                    self.max_allowed_users = 0
            
            if self.admin_account_type != self.AdminAccountType.TRIAL:
                self.trial_extension_requested = False
                self.trial_extension_reason = None
        
        # --- Stage 2: Handle Deactivation of Managed Users based on Max User Limit Changes ---
        if is_existing_admin_update:
            old_limit_from_instance_load = self._original_max_allowed_users if self._original_max_allowed_users is not None else 0
            effective_new_limit_being_saved = self.max_allowed_users if self.max_allowed_users is not None else 0

            should_deactivate_based_on_limit = False
            if not will_be_admin_access_active_after_save:
                if old_limit_from_instance_load > 0 :
                     should_deactivate_based_on_limit = True
            elif effective_new_limit_being_saved < old_limit_from_instance_load:
                 should_deactivate_based_on_limit = True

            if should_deactivate_based_on_limit:
                current_active_users_count_in_db = CustomUser.objects.filter(
                    company_admin_id=self.pk, role=self.USER, is_active=True, approved_by__isnull=False
                ).count()

                if effective_new_limit_being_saved < current_active_users_count_in_db:
                    self._deactivate_managed_users(
                        reason=f"Admin {self.email} user capacity changed to {effective_new_limit_being_saved} or account access ended."
                    )
        
        super().save(*args, **kwargs)

        # --- Stage 3: Update original value trackers on the instance after successful save ---
        if self.pk: 
            self._original_max_allowed_users = self.max_allowed_users
            self._original_admin_account_type = self.admin_account_type
            self._original_access_ends_at = self.access_ends_at