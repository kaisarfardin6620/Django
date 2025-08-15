import json
from django.conf import settings
from openai import OpenAI
from django.contrib.auth import get_user_model
from django.db.models.fields.files import FieldFile
from asgiref.sync import sync_to_async

User = get_user_model()
client = OpenAI(api_key=settings.OPENAI_API_KEY)

def get_user_personal_data(user_id):
    try:
        user = User.objects.select_related('profile').get(id=user_id)
        user_data = {"id":str(user.id),"username":user.username,"first_name":user.first_name,"last_name":user.last_name}
        profile = getattr(user,"profile",None)
        if profile:
            profile_data = {"bio":profile.bio,"date_of_birth":str(profile.date_of_birth),"age":profile.age,"gender":profile.gender,"phone_number":profile.phone_number}
            if profile.profile_picture and isinstance(profile.profile_picture,FieldFile):
                profile_data["profile_picture_url"]=profile.profile_picture.url
            user_data.update(profile_data)
        return user_data
    except User.DoesNotExist: return {"error":f"User with id {user_id} not found"}
    except Exception as e: return {"error":f"Unexpected error: {str(e)}"}

def build_system_prompt(user_data=None):
    base_prompt = "You are Lannister, a helpful, context-aware AI assistant. You provide thoughtful advice, can discuss multiple topics, and remember conversation context within the session. You are polite, concise, and accurate."
    if user_data:
        user_info = f"\n\nUser profile information (do NOT hallucinate or make up anything):\nUsername: {user_data.get('username','N/A')}\nFirst Name: {user_data.get('first_name','N/A')}\nLast Name: {user_data.get('last_name','N/A')}\nBio: {user_data.get('bio','N/A')}\nAge: {user_data.get('age','N/A')}\nGender: {user_data.get('gender','N/A')}\nPhone: {user_data.get('phone_number','N/A')}\nProfile Picture: {user_data.get('profile_picture_url','N/A')}\n"
        return base_prompt + user_info
    else: return base_prompt

def generate_title_from_message(message_text):
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role":"system","content":"You are an AI that generates a concise, descriptive title for a conversation based on the user's first message. Return only the title."},{"role":"user","content":message_text}],
            max_tokens=20
        )
        return response.choices[0].message.content.strip().replace('"','')
    except Exception as e:
        print(f"Error generating title: {e}")
        return None

def generate_ai_response(conversation,user,user_message_text):
    history_data = list(conversation.messages.order_by('created_at').values('role','text'))
    user_data = get_user_personal_data(user.id)
    system_message = {"role":"system","content":build_system_prompt(user_data)}
    formatted_messages = [system_message] + [{"role":m["role"],"content":m["text"]} for m in history_data] + [{"role":"user","content":user_message_text}]
    response = client.chat.completions.create(model="gpt-4o-mini", messages=formatted_messages)
    return response.choices[0].message.content

async def generate_ai_response_async(conversation,user,user_message_text):
    return await sync_to_async(generate_ai_response)(conversation,user,user_message_text)
