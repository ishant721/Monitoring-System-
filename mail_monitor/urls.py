from django.urls import path
from . import views

app_name = 'mail_monitor'

urlpatterns = [
    path('setup/', views.user_setup_app_password, name='user_setup'),
    path('admin/config/', views.admin_manage_email_config, name='admin_config'),
    path('admin/inbox/', views.admin_email_inbox, name='admin_inbox'),
    path('admin/inbox/user/<int:user_id>/', views.admin_email_inbox, name='admin_user_inbox'),
    path('admin/inbox/email/<int:email_id>/', views.admin_email_detail, name='admin_email_detail'),
    path('admin/status/', views.admin_monitoring_status, name='admin_monitoring_status'),
    path('admin/setup-credentials/<int:user_id>/', views.user_setup_app_password, name='admin_setup_user_credentials'),
]
