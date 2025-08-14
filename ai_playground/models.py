from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid

def attachment_upload_to(instance, filename):
    return f"ai_playground/{instance.conversation.user.id}/{instance.conversation.id}/{uuid.uuid4().hex}_{filename}"

class AIPlayground(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ai_playgrounds')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} ({self.user.username})"

class Conversation(models.Model):
    playground = models.ForeignKey(AIPlayground, on_delete=models.CASCADE, related_name='conversations')
    title = models.CharField(max_length=255, default='New Conversation')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='conversations')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_archived = models.BooleanField(default=False)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f"{self.title} ({self.created_by.username})"


class Message(models.Model):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('assistant', 'Assistant'),
        ('system', 'System'),
    ]
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    text = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(blank=True, null=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"[{self.role}] {self.text[:40]}"


class Attachment(models.Model):
    ATTACHMENT_TYPES = [
        ('image', 'Image'),
        ('file', 'File'),
        ('audio', 'Audio'),
        ('other', 'Other'),
    ]
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='attachments')
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(upload_to=attachment_upload_to)
    filename = models.CharField(max_length=512)
    content_type = models.CharField(max_length=255, blank=True)
    size = models.BigIntegerField(null=True, blank=True)
    attachment_type = models.CharField(max_length=20, choices=ATTACHMENT_TYPES, default='file')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.filename