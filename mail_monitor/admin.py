# mail_monitor/admin.py

from django.contrib import admin
from .models import CompanyEmailConfig, EmailAccount, MonitoredEmail, EmailAttachment

@admin.register(CompanyEmailConfig)
class CompanyEmailConfigAdmin(admin.ModelAdmin):
    """Admin interface for the company-wide email server settings."""
    list_display = ('admin', 'imap_server', 'updated_at')
    search_fields = ('admin__email', 'imap_server')
    readonly_fields = ('admin', 'updated_at')
    
    def has_add_permission(self, request):
        return False

@admin.register(EmailAccount)
class EmailAccountAdmin(admin.ModelAdmin):
    """Admin interface for viewing which users have provided their credentials."""
    list_display = ('user', 'is_active', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('user__email',)
    readonly_fields = ('user', 'created_at')
    
    def has_add_permission(self, request):
        return False
    def has_change_permission(self, request, obj=None):
        return False

class EmailAttachmentInline(admin.TabularInline):
    """Allows viewing attachments directly within the email detail page."""
    model = EmailAttachment
    extra = 0
    readonly_fields = ('filename', 'content_type', 'file')
    can_delete = False
    def has_add_permission(self, request, obj=None):
        return False

# --- THIS IS THE CORRECTED SECTION ---
@admin.register(MonitoredEmail)
class MonitoredEmailAdmin(admin.ModelAdmin):
    """Admin interface for viewing the emails that have been fetched."""
    
    # Use the new, correct field names
    list_display = ('subject', 'sender', 'account', 'direction', 'date', 'has_attachments')
    
    # Filter by the new 'direction' field instead of 'folder'
    list_filter = ('direction', 'has_attachments', 'date', 'account__user__email')
    
    # The search fields are now more specific
    search_fields = ('subject', 'sender', 'recipients_to', 'recipients_cc', 'recipients_bcc', 'body')
    
    # The readonly_fields list now uses all the new, correct field names
    readonly_fields = (
        'account', 'message_id', 'direction', 'sender', 
        'recipients_to', 'recipients_cc', 'recipients_bcc', 
        'subject', 'body', 'date', 
        'has_attachments', 'fetched_at'
    )
    
    # Add the attachment viewer to the email detail page.
    inlines = [EmailAttachmentInline]

    # Prevent anyone from adding or changing emails through the admin interface.
    def has_add_permission(self, request):
        return False
        
    def has_change_permission(self, request, obj=None):
        # Allow viewing the object, but not saving any changes
        return True 

    def get_readonly_fields(self, request, obj=None):
        # Make all fields readonly in the change view
        if obj: # obj is not None, so this is a change page
            return self.readonly_fields
        return super().get_readonly_fields(request, obj)