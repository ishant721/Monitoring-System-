# accounts/urls.py

from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    # --- Authentication & Registration ---
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # --- OTP and Approval Flow ---
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
    path('resend-registration-otp/', views.resend_registration_email_otp_view, name='resend_registration_otp'),
    path('registration-pending-approval/', views.registration_pending_approval_view, name='registration_pending_approval'),

    # --- Password Reset ---
    path('password-reset-request/', views.password_reset_request_view, name='password_reset_request'),
    path('set-new-password/', views.set_new_password_view, name='set_new_password'),

    # --- Dashboards ---
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('dashboard/superadmin/', views.superadmin_dashboard_view, name='superadmin_dashboard'),
    path('dashboard/admin/', views.admin_dashboard_view, name='admin_dashboard'),
    path('dashboard/user/', views.user_dashboard_view, name='user_dashboard'),
   
    # --- Approval Actions ---
    path('approve/admin/<int:user_id>/', views.approve_admin_view, name='approve_admin'),
    path('approve/user/<int:user_id>/', views.approve_user_view, name='approve_user'),
    
    # --- User Creation by Admins/Superadmins ---
    path('superadmin/add-admin/', views.superadmin_add_admin_view, name='superadmin_add_admin'),
    path('admin/add-user/', views.admin_add_user_view, name='admin_add_user'),

    # --- User Status Management by Admins ---
    path('admin/manage-user/<int:user_id>/activate/', views.admin_manage_user_status_view, {'activate': True}, name='admin_activate_user'),
    path('admin/manage-user/<int:user_id>/deactivate/', views.admin_manage_user_status_view, {'activate': False}, name='admin_deactivate_user'),
    
    # --- Admin Account Management by Superadmins ---
    path('superadmin/manage-admin-access/<int:admin_id>/', views.superadmin_manage_admin_access_view, name='superadmin_manage_admin_access'),
    path('admin/request-trial-extension/', views.admin_request_trial_extension_view, name='admin_request_trial_extension'),

    # --- User-specific pages ---
    path('user-detail/<int:user_id>/', views.admin_view_user_detail, name='admin_view_user_detail'),
    path('download-agent/', views.user_download_agent_view, name='user_download_agent'),
    
    # The incorrect line has been removed from here.
]