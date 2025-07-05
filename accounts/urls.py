# Adding URL for feature restrictions management to accounts/urls.py

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

    # Break Schedule Management (Admin only)
    path('manage-break-schedules/', views.manage_break_schedules_view, name='manage_break_schedules'),
    path('break-overview/', views.break_overview_view, name='break_overview'),
    path('bulk-break-management/', views.bulk_break_management_view, name='bulk_break_management'),
    path('edit-company-break/<int:break_id>/', views.edit_company_break_view, name='edit_company_break'),
    path('delete-company-break/<int:break_id>/', views.delete_company_break_view, name='delete_company_break'),
    path('edit-user-break/<int:break_id>/', views.edit_user_break_view, name='edit_user_break'),
    path('delete-user-break/<int:break_id>/', views.delete_user_break_view, name='delete_user_break'),

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
    path('superadmin/deactivate-admin/<int:admin_id>/', views.superadmin_deactivate_admin_view, name='superadmin_deactivate_admin'),
    path('superadmin/activate-admin/<int:admin_id>/', views.superadmin_activate_admin_view, name='superadmin_activate_admin'),
    path('superadmin/extend-trial/<int:admin_id>/', views.superadmin_extend_trial_view, name='superadmin_extend_trial'),
    path('admin/configure-monitoring/<int:user_id>/', views.admin_configure_monitoring_view, name='admin_configure_monitoring'),
    path('admin/bulk-configure-monitoring/', views.bulk_configure_monitoring_view, name='admin_bulk_configure_monitoring'),
    path('admin/manage-features/<int:admin_id>/', views.superadmin_manage_feature_restrictions_view, name='superadmin_manage_feature_restrictions'),

    # User Management (Admin only)
    path('approve-user/<int:user_id>/', views.approve_user_view, name='approve_user'),
    path('user-detail/<int:user_id>/', views.admin_view_user_detail, name='admin_view_user_detail'),

    # Break Schedule Management (Admin only)
    path('manage-break-schedules/', views.manage_break_schedules_view, name='manage_break_schedules'),
    path('delete-user-break/<int:break_id>/', views.delete_user_break_view, name='delete_user_break'),
]