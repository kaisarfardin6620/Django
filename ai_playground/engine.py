import json
from django.conf import settings
from openai import OpenAI
from authentication.models import UserProfile
from django.contrib.auth import get_user_model
from django.db.models.fields.files import FieldFile
from asgiref.sync import sync_to_async

User = get_user_model()
client = OpenAI(api_key=settings.OPENAI_API_KEY)

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
        response = client.chat.completions.create(
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

def generate_ai_response(conversation, user, user_message_text):
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

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=formatted_history,
        tools=tools,
        tool_choice="auto"
    )

    response_message = response.choices[0].message

    if response_message.tool_calls:
        tool_call = response_message.tool_calls[0]
        function_name = tool_call.function.name
        function_to_call = get_user_personal_data
        function_args = {"user_id": str(user.id)}
        function_response = function_to_call(**function_args)

        formatted_history.append({
            "role": "tool",
            "tool_call_id": tool_call.id,
            "name": function_name,
            "content": json.dumps(function_response)
        })

        second_response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=formatted_history
        )
        return second_response.choices[0].message.content
    else:
        return response_message.content

# Add this async wrapper function
async def generate_ai_response_async(conversation, user, user_message_text):
    """Async wrapper for generate_ai_response"""
    return await sync_to_async(generate_ai_response)(conversation, user, user_message_text)