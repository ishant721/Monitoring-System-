from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser, CompanyBreakSchedule, UserBreakSchedule, AdminFeatureRestrictions
from .forms import CustomUserCreationForm, CustomUserChangeForm

class CustomUserAdmin(BaseUserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm
    model = CustomUser

    list_display = [
        'email', 'first_name', 'last_name', 'role',
        'is_active', 'is_staff', 'is_superuser',
        'is_email_verified', 'phone_number',
        'company_admin', 'approved_by',
        'max_allowed_users',
        'date_joined'
    ]
    list_filter = [
        'role', 'is_active', 'is_staff', 'is_superuser',
        'is_email_verified'
    ]
    search_fields = ['email', 'first_name', 'last_name', 'phone_number']
    ordering = ['-date_joined', 'email']

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'phone_number')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser',)}),
        ('Role and Hierarchy', {'fields': ('role', 'company_admin', 'approved_by', 'max_allowed_users')}),
        ('Verification Status', {'fields': ('is_email_verified', 'email_otp', 'otp_created_at')}),
        ('Groups and User Permissions', {'fields': ('groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email', 'password', 'password2',
                'first_name', 'last_name',
                'role', 'phone_number',
                'company_admin_email',
                'max_allowed_users',
                'is_staff', 'is_superuser',
            ),
        }),
    )

admin.site.register(CustomUser, CustomUserAdmin)

@admin.register(CompanyBreakSchedule)
class CompanyBreakScheduleAdmin(admin.ModelAdmin):
    list_display = ['name', 'admin', 'day', 'start_time', 'end_time', 'is_active', 'created_at']
    list_filter = ['day', 'is_active', 'admin__email']
    search_fields = ['name', 'admin__email']
    ordering = ['admin__email', 'day', 'start_time']
    
    fieldsets = (
        ('Break Information', {
            'fields': ('admin', 'name', 'day', 'start_time', 'end_time', 'is_active')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    readonly_fields = ('created_at', 'updated_at')

@admin.register(UserBreakSchedule)
class UserBreakScheduleAdmin(admin.ModelAdmin):
    list_display = ['name', 'user', 'day', 'start_time', 'end_time', 'is_on_leave', 'is_active', 'created_at']
    list_filter = ['day', 'is_active', 'is_on_leave', 'user__company_admin__email']
    search_fields = ['name', 'user__email', 'leave_reason']
    ordering = ['user__email', 'day', 'start_time']
    
    fieldsets = (
        ('Break Information', {
            'fields': ('user', 'name', 'day', 'start_time', 'end_time', 'is_active')
        }),
        ('Leave Management', {
            'fields': ('is_on_leave', 'leave_start_date', 'leave_end_date', 'leave_reason'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    readonly_fields = ('created_at', 'updated_at')

@admin.register(AdminFeatureRestrictions)
class AdminFeatureRestrictionsAdmin(admin.ModelAdmin):
    list_display = ['admin', 'can_use_activity_monitoring', 'can_use_video_recording', 'can_use_keystroke_logging', 'created_at']
    list_filter = ['can_use_activity_monitoring', 'can_use_video_recording', 'can_use_keystroke_logging', 'can_use_email_monitoring']
    search_fields = ['admin__email']
    ordering = ['admin__email']
    
    fieldsets = (
        ('Admin', {
            'fields': ('admin',)
        }),
        ('Core Monitoring Features', {
            'fields': ('can_use_activity_monitoring', 'can_use_network_monitoring', 'can_use_screenshot_capturing')
        }),
        ('Advanced Monitoring Features', {
            'fields': ('can_use_live_streaming', 'can_use_video_recording', 'can_use_keystroke_logging', 'can_use_email_monitoring')
        }),
        ('Administrative Features', {
            'fields': ('can_configure_monitoring', 'can_manage_email_config')
        }),
        ('Retention Limits', {
            'fields': ('max_screenshot_retention_days', 'max_video_retention_days'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    readonly_fields = ('created_at', 'updated_at')