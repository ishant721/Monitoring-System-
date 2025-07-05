# monitor_app/permissions.py

from rest_framework.permissions import BasePermission
from .models import Agent

class IsAdminOrSuperadmin(BasePermission):
    """
    Grants permission if the user is an active staff member (Admin or Superadmin).
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_staff

class IsOwnerOfAgent(BasePermission):
    """
    Custom permission to only allow an agent's managing admin (or a superadmin)
    to view or edit it.
    """
    def has_object_permission(self, request, view, obj):
        # The 'obj' here is the Agent instance being checked.
        user = request.user

        # Rule 1: Superadmins can do anything.
        if user.is_superadmin:
            return True
        
        # Rule 2: An Admin can access the agent if they are the user's company_admin.
        if user.role == 'ADMIN' and obj.user.company_admin == user:
            return True
            
        # Rule 3: A regular user can access their own agent's data.
        # (You might want this for a user-facing view later)
        if user.role == 'USER' and obj.user == user:
            return True

        # If none of the above, deny permission.
        return False


class AgentPermission(BasePermission):
    """
    Permission class for agent API endpoints.
    Allows access if the request is authenticated via AgentAPIKeyAuthentication.
    """
    def has_permission(self, request, view):
        # Allow access if agent_id is present in request (set by AgentAPIKeyAuthentication)
        return hasattr(request, 'agent_id') and request.agent_id is not None