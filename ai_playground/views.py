from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from django.db import transaction

from .models import AIPlayground, Conversation, Message, Attachment
from .serializers import ConversationSerializer, MessageSerializer, AttachmentSerializer
from .engine import generate_title_from_message, generate_ai_response

class ConversationViewSet(viewsets.ModelViewSet):
    serializer_class = ConversationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Conversation.objects.filter(created_by=self.request.user)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def rename(self, request, pk=None):
        convo = self.get_object()
        title = request.data.get('title')
        if not title:
            return Response({"detail":"title required"}, status=status.HTTP_400_BAD_REQUEST)
        convo.title = title
        convo.save()
        return Response(self.get_serializer(convo).data)

    @action(detail=True, methods=['post'])
    def archive(self, request, pk=None):
        convo = self.get_object()
        convo.is_archived = True
        convo.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['get'])
    def search(self, request):
        q = request.query_params.get('q','').strip()
        qs = self.get_queryset()
        if q: qs = qs.filter(title__icontains=q)
        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = self.get_serializer(page,many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(qs,many=True)
        return Response(serializer.data)

class AttachmentViewSet(viewsets.ModelViewSet):
    serializer_class = AttachmentSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_queryset(self):
        return Attachment.objects.filter(uploaded_by=self.request.user)

    def perform_create(self, serializer):
        convo = serializer.validated_data['conversation']
        if convo.created_by != self.request.user:
            raise PermissionError("Not allowed")
        f = serializer.validated_data.get('file')
        serializer.save(
            uploaded_by=self.request.user,
            filename=getattr(f,'name',''),
            size=getattr(f,'size',None),
            content_type=getattr(f,'content_type','')
        )

class ChatView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        with transaction.atomic():
            conversation_id = request.data.get('conversation_id')
            user = request.user
            conversation = None
            if conversation_id:
                try:
                    conversation = Conversation.objects.get(id=conversation_id, created_by=user)
                except Conversation.DoesNotExist:
                    return Response({"error":"Conversation not found"},status=404)
            if not conversation:
                playground,_ = AIPlayground.objects.get_or_create(user=user, defaults={'title':f"{user.username}'s Playground"})
                conversation = Conversation.objects.create(playground=playground, created_by=user, title="New Conversation")

            message_data = {
                'conversation': conversation.id,
                'text': request.data.get('text'),
                'attachments_data': request.FILES.getlist('attachments_data'),
            }
            user_message_serializer = MessageSerializer(data=message_data, context={'request':request})
            user_message_serializer.is_valid(raise_exception=True)
            user_message = user_message_serializer.save(role='user')

            if conversation.title == "New Conversation":
                new_title = generate_title_from_message(user_message.text)
                if new_title:
                    conversation.title = new_title
                    conversation.save()

            ai_text = generate_ai_response(conversation, user, user_message.text)
            Message.objects.create(conversation=conversation, role='assistant', text=ai_text)

            conversation_serializer = ConversationSerializer(conversation, context={'request':request})
            return Response(conversation_serializer.data, status=200)
