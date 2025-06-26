from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser
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