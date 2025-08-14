import os
import django
from django.core.asgi import get_asgi_application

# Set Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')

# Setup Django before importing other modules
django.setup()

# Now import Django Channels modules after Django is set up
from channels.routing import ProtocolTypeRouter, URLRouter
from ai_playground.routing import websocket_urlpatterns
from ai_playground.middleware import JWTAuthMiddleware

# Get the Django ASGI application early to ensure Django is fully initialized
django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": JWTAuthMiddleware(
        URLRouter(websocket_urlpatterns)
    ),
})