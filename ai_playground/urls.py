from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ConversationViewSet, AttachmentViewSet, ChatView

router = DefaultRouter()
router.register(r'conversations', ConversationViewSet, basename='conversation')
router.register(r'attachments', AttachmentViewSet, basename='attachment')

urlpatterns = [
    path('', include(router.urls)),
    path('chat/', ChatView.as_view(), name='chat-view'),
]