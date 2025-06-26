from django.conf import settings
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth.models import AnonymousUser
from .models import CustomUser

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not hasattr(request, 'user') or request.user is None:
            request.user = AnonymousUser()

        raw_token = request.COOKIES.get(settings.SIMPLE_JWT.get('AUTH_COOKIE', 'access_token'))
        jwt_user_authenticated_and_valid = False

        if raw_token:
            try:
                access_token = AccessToken(raw_token)
                user_id = access_token[settings.SIMPLE_JWT['USER_ID_CLAIM']]
                user_from_token = CustomUser.objects.get(id=user_id)

                can_login_via_jwt = user_from_token.is_active and \
                                   user_from_token.is_email_verified
                
                if user_from_token.role != CustomUser.SUPERADMIN:
                    can_login_via_jwt = can_login_via_jwt and (user_from_token.approved_by is not None)

                if can_login_via_jwt:
                    request.user = user_from_token
                    jwt_user_authenticated_and_valid = True
            except (InvalidToken, TokenError, CustomUser.DoesNotExist):
                pass

        if not jwt_user_authenticated_and_valid and not request.user.is_authenticated:
            request.user = AnonymousUser()

        response = self.get_response(request)
        return response