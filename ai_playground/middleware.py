from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from urllib.parse import parse_qs
import logging

User = get_user_model()
logger = logging.getLogger(__name__)

class JWTAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        if scope['type'] != 'websocket': return await super().__call__(scope, receive, send)
        query_params = parse_qs(scope.get('query_string',b'').decode('utf-8'))
        token = query_params.get('token',[None])[0]
        if not token:
            headers = dict(scope.get('headers',[]))
            authorization = headers.get(b'authorization',b'').decode('utf-8')
            if authorization.startswith('Bearer '): token = authorization[7:]
        scope['user'] = AnonymousUser()
        if token:
            try:
                access_token = AccessToken(token)
                user = await self.get_user_from_token(access_token)
                if user:
                    scope['user'] = user
                    logger.info(f"WebSocket authenticated user: {user.username}")
                else: logger.warning("Invalid user from token")
            except (InvalidToken,TokenError) as e: logger.warning(f"JWT token validation failed: {str(e)}")
            except Exception as e: logger.error(f"Unexpected error during JWT validation: {str(e)}")
        return await super().__call__(scope, receive, send)

    @database_sync_to_async
    def get_user_from_token(self, access_token):
        try:
            user_id = access_token.payload.get('user_id')
            if user_id: return User.objects.get(id=user_id)
        except User.DoesNotExist: logger.warning(f"User with id {user_id} not found")
        except Exception as e: logger.error(f"Error getting user from token: {str(e)}")
        return None
