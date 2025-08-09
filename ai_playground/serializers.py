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
    attachments = AttachmentSerializer(source='conversation.attachments', many=True, read_only=True)
    class Meta:
        model = Message
        fields = ['id','conversation','role','text','metadata','created_at','attachments']
        read_only_fields = ['id','created_at','attachments']


class ConversationSerializer(serializers.ModelSerializer):
    last_message = serializers.SerializerMethodField()
    messages_count = serializers.IntegerField(source='messages.count', read_only=True)

    class Meta:
        model = Conversation
        fields = ['id','playground','title','created_by','created_at','updated_at','is_archived','last_message','messages_count']
        read_only_fields = ['id','created_by','created_at','updated_at','messages_count','last_message']

    def get_last_message(self, obj):
        last = obj.messages.order_by('-created_at').first()
        return MessageSerializer(last, context=self.context).data if last else None

    def create(self, validated_data):
        request = self.context.get('request')
        if request and not validated_data.get('created_by'):
            validated_data['created_by'] = request.user
        return super().create(validated_data)

