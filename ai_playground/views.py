from django.shortcuts import render
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import AIPlayground, Conversation, Message, Attachment
from .serializers import ConversationSerializer, MessageSerializer, AttachmentSerializer
from django.shortcuts import get_object_or_404
from rest_framework.parsers import MultiPartParser, FormParser

class ConversationViewSet(viewsets.ModelViewSet):
    queryset = Conversation.objects.all()
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
        if q:
            qs = qs.filter(title__icontains=q)  
        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)


class MessageViewSet(viewsets.ModelViewSet):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        convo_id = self.request.query_params.get('conversation')
        qs = Message.objects.filter(conversation__created_by=self.request.user)
        if convo_id:
            qs = qs.filter(conversation_id=convo_id)
        return qs

    def perform_create(self, serializer):
        conversation = serializer.validated_data['conversation']
        if conversation.created_by != self.request.user:
            raise PermissionError("Not allowed")
        serializer.save()


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
            filename=getattr(f, 'name', ''),
            size=getattr(f, 'size', None),
            content_type=getattr(f, 'content_type', '')
        )

