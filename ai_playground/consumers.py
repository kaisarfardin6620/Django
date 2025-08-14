import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .models import AIPlayground, Conversation, Message
from .serializers import ConversationSerializer, MessageSerializer
from .engine import generate_title_from_message, generate_ai_response_async

User = get_user_model()
logger = logging.getLogger(__name__)

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]
        
        # Check authentication
        if self.user.is_anonymous:
            await self.close()
            return
        
        # Get conversation_id from URL if provided
        self.conversation_id = self.scope.get('url_route', {}).get('kwargs', {}).get('conversation_id')
        
        await self.accept()
        
        # Send connection confirmation
        await self.send(text_data=json.dumps({
            'type': 'connection_established',
            'message': 'Connected to AI chat'
        }))

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message_type = data.get('type', 'chat_message')
            
            if message_type == 'chat_message':
                await self.handle_chat_message(data)
                
        except Exception as e:
            logger.error(f"Error in receive: {str(e)}")
            await self.send_error(f"Error: {str(e)}")

    async def handle_chat_message(self, data):
        try:
            message_text = data.get('text', '').strip()
            if not message_text:
                return

            conversation_id = data.get('conversation_id') or self.conversation_id
            
            # Get or create conversation
            conversation = await self.get_or_create_conversation(conversation_id)
            
            # Create user message
            user_message = await self.create_user_message(conversation, message_text)

            # Send user message confirmation
            await self.send(text_data=json.dumps({
                'type': 'user_message_saved',
                'message': await self.serialize_message(user_message)
            }))

            # Generate title if new conversation
            if conversation.title == "New Conversation":
                new_title = await database_sync_to_async(generate_title_from_message)(message_text)
                if new_title:
                    conversation.title = new_title
                    await database_sync_to_async(conversation.save)()

            # Show typing indicator
            await self.send(text_data=json.dumps({
                'type': 'ai_typing',
                'status': True
            }))

            # Generate AI response
            ai_response = await generate_ai_response_async(conversation, self.user, message_text)

            # Create AI message
            ai_message = await self.create_ai_message(conversation, ai_response)

            # Send AI response
            await self.send(text_data=json.dumps({
                'type': 'ai_message',
                'message': await self.serialize_message(ai_message)
            }))

            # Hide typing indicator
            await self.send(text_data=json.dumps({
                'type': 'ai_typing',
                'status': False
            }))

        except Exception as e:
            logger.error(f"Error handling chat message: {str(e)}")
            await self.send_error(f"Error: {str(e)}")

    # Database operations
    @database_sync_to_async
    def get_or_create_conversation(self, conversation_id=None):
        if conversation_id:
            try:
                return Conversation.objects.get(id=conversation_id, created_by=self.user)
            except Conversation.DoesNotExist:
                pass
        
        # Create new conversation
        playground, _ = AIPlayground.objects.get_or_create(
            user=self.user, 
            defaults={'title': f"{self.user.username}'s Playground"}
        )
        return Conversation.objects.create(
            playground=playground,
            created_by=self.user,
            title="New Conversation"
        )

    @database_sync_to_async
    def create_user_message(self, conversation, text):
        return Message.objects.create(
            conversation=conversation,
            role='user',
            text=text
        )

    @database_sync_to_async
    def create_ai_message(self, conversation, text):
        return Message.objects.create(
            conversation=conversation,
            role='assistant',
            text=text
        )

    @database_sync_to_async
    def serialize_message(self, message):
        return MessageSerializer(message).data

    async def send_error(self, message):
        await self.send(text_data=json.dumps({
            'type': 'error',
            'message': message
        }))