from rest_framework import serializers
from .models import Message, Attachment, Conversation, AIPlayground

class AttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment
        fields = ['id', 'file', 'created_at']

class MessageSerializer(serializers.ModelSerializer):
    # Removed the redundant source argument
    attachments = AttachmentSerializer(many=True, read_only=True)

    class Meta:
        model = Message
        fields = ['id', 'conversation', 'role', 'text', 'attachments', 'created_at']

class ConversationSerializer(serializers.ModelSerializer):
    messages = MessageSerializer(many=True, read_only=True)

    class Meta:
        model = Conversation
        fields = ['id', 'playground', 'created_by', 'title', 'messages', 'created_at']

class AIPlaygroundSerializer(serializers.ModelSerializer):
    conversations = ConversationSerializer(many=True, read_only=True)

    class Meta:
        model = AIPlayground
        fields = ['id', 'user', 'title', 'conversations', 'created_at']
