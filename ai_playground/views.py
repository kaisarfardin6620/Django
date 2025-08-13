from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.conf import settings
import openai
import json  
from django.contrib.auth import get_user_model 
from django.db.models.fields.files import FieldFile 

from .models import AIPlayground, Conversation, Message, Attachment
from .serializers import ConversationSerializer, MessageSerializer, AttachmentSerializer
from authentication.models import UserProfile 

User = get_user_model() 

openai.api_key = settings.OPENAI_API_KEY

def get_user_personal_data(user_id):
    try:
        user = User.objects.select_related('profile').get(id=user_id)
        
        user_data = {
            "id": str(user.id),
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name
        }
        
        if hasattr(user, 'profile'):
            profile = user.profile
            profile_data = {
                "bio": profile.bio,
                "date_of_birth": str(profile.date_of_birth),
                "age": profile.age,
                "gender": profile.gender,
                "phone_number": profile.phone_number,
            }
            if profile.profile_picture and isinstance(profile.profile_picture, FieldFile):
                 profile_data['profile_picture_url'] = profile.profile_picture.url
                 
            user_data.update(profile_data)
        
        return user_data
    except User.DoesNotExist:
        return {"error": f"User with id {user_id} not found."}

def generate_title_from_message(message_text):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant that generates a concise title for a conversation based on the first user message. Respond with only the title and no other text."
                },
                {
                    "role": "user",
                    "content": message_text
                }
            ]
        )
        title = response.choices[0].message.content.strip().strip('"')
        return title[:50]
    except Exception as e:
        print(f"Error generating title: {e}")
        return "New Conversation"

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
                    return Response({"error": "Conversation not found or you don't have permission."}, status=status.HTTP_404_NOT_FOUND)
            
            if not conversation:
                playground, _ = AIPlayground.objects.get_or_create(user=user, defaults={'title': f"{user.username}'s Playground"})
                conversation = Conversation.objects.create(playground=playground, created_by=user, title="New Conversation")

            message_data = {
                'conversation': conversation.id,
                'text': request.data.get('text'),
                'attachments_data': request.FILES.getlist('attachments_data'),
            }
            user_message_serializer = MessageSerializer(data=message_data, context={'request': request})
            user_message_serializer.is_valid(raise_exception=True)
            user_message = user_message_serializer.save(role='user')

            if conversation.title == "New Conversation":
                new_title = generate_title_from_message(user_message.text)
                if new_title:
                    conversation.title = new_title
                    conversation.save()

            history_data = list(conversation.messages.order_by('created_at').values('role', 'text'))
            
            system_message = {
                "role": "system",
                "content": f"You are a helpful AI assistant. Your user's username is '{user.username}'. When asked for personal information, you have a tool named 'get_user_personal_data' which you must use. Do not make up any personal data. You can access the user's details only by using this tool."
            }
            
            formatted_history = [system_message]
            formatted_history.extend([{"role": m["role"], "content": m["text"]} for m in history_data])
            
            tools = [{
                "type": "function",
                "function": {
                    "name": "get_user_personal_data",
                    "description": "Gets personal data for the user, such as their username, first name, last name, and email. This is useful for personalizing responses or answering questions about the user's identity.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "user_id": {
                                "type": "string",
                                "description": "The unique ID of the user.",
                            }
                        },
                        "required": ["user_id"]
                    },
                }
            }]
            
            response = openai.ChatCompletion.create(
                model="gpt-4o-mini",
                messages=formatted_history,
                tools=tools,
                tool_choice="auto", 
            )
            
            response_message = response.choices[0].message

            if hasattr(response_message, 'tool_calls') and response_message.tool_calls:
                tool_calls = response_message.tool_calls
                function_name = tool_calls[0].function.name
                function_to_call = globals().get(function_name)
                
                function_args = {"user_id": str(user.id)}
                
                function_response = function_to_call(**function_args)

                formatted_history.append(response_message)
                formatted_history.append({
                    "tool_call_id": tool_calls[0].id,
                    "role": "tool",
                    "name": function_name,
                    "content": json.dumps(function_response)
                })
                
                second_response = openai.ChatCompletion.create(
                    model="gpt-4o-mini",
                    messages=formatted_history,
                )
                ai_text = second_response.choices[0].message.content
            else:
                ai_text = response_message.content

            Message.objects.create(
                conversation=conversation,
                role='assistant',
                text=ai_text
            )
            
            conversation_serializer = ConversationSerializer(conversation, context={'request': request})
            return Response(conversation_serializer.data, status=status.HTTP_200_OK)
