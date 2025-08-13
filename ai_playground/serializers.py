from rest_framework import serializers
from .models import AIPlayground, Conversation, Message, Attachment
from django.contrib.auth.models import User

class AttachmentSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = Attachment
        fields = ['id','filename','file','url','content_type','size','attachment_type','created_at']
        read_only_fields = ['id','created_at','size','content_type']

    def get_url(self, obj):
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(obj.file.url)
        return obj.file.url

class MessageSerializer(serializers.ModelSerializer):
    attachments_data = serializers.ListField(
        child=serializers.FileField(), write_only=True, required=False
    )
    attachments = AttachmentSerializer(many=True, read_only=True, source='attachments_for_message')

    class Meta:
        model = Message
        fields = ['id', 'conversation', 'role', 'text', 'metadata', 'created_at', 'attachments', 'attachments_data']
        read_only_fields = ['id', 'created_at', 'attachments']
        extra_kwargs = {
            'conversation': {'write_only': True},
            'role': {'write_only': True},
        }

    def create(self, validated_data):
        attachments_data = validated_data.pop('attachments_data', [])
        
        validated_data['role'] = 'user'
        
        message = Message.objects.create(**validated_data)
        
        for file in attachments_data:
            Attachment.objects.create(
                conversation=message.conversation,
                uploaded_by=message.conversation.created_by,
                file=file,
                filename=file.name,
                content_type=file.content_type,
                size=file.size
            )
        
        return message

class ConversationSerializer(serializers.ModelSerializer):
    messages_count = serializers.IntegerField(source='messages.count', read_only=True)
    messages = MessageSerializer(many=True, read_only=True)

    class Meta:
        model = Conversation
        fields = ['id','playground','title','created_by','created_at','updated_at','is_archived','messages_count', 'messages']
        read_only_fields = ['id','created_by','created_at','updated_at','messages_count', 'messages']

    def create(self, validated_data):
        request = self.context.get('request')
        if request and not validated_data.get('created_by'):
            validated_data['created_by'] = request.user
        return super().create(validated_data)