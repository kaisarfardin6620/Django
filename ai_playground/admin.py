from django.contrib import admin
from .models import AIPlayground,Conversation, Message, Attachment

@admin.register(AIPlayground)
class AIPlaygroundAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'created_at', 'updated_at')
    search_fields = ('title', 'user__username')
    list_filter = ('created_at', 'updated_at')
    ordering = ('-created_at',)

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.select_related('user')
    
@admin.register(Conversation)    
class ConversationAdmin(admin.ModelAdmin):
    list_display = ('title', 'playground', 'created_by', 'created_at', 'updated_at', 'is_archived')
    search_fields = ('title', 'playground__title', 'created_by__username')
    list_filter = ('created_at', 'updated_at', 'is_archived')
    ordering = ('-updated_at',)

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.select_related('playground', 'created_by')
    
@admin.register(Message) 
class MessageAdmin(admin.ModelAdmin):
    list_display = ('conversation', 'role', 'text', 'created_at')
    search_fields = ('conversation__title', 'text')
    list_filter = ('role', 'created_at')
    ordering = ('-created_at',)

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.select_related('conversation')

@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    list_display = ('conversation', 'attachment_type', 'file', 'created_at')
    search_fields = ('conversation__title', 'attachment_type')
    list_filter = ('attachment_type', 'created_at')
    ordering = ('-created_at',)

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.select_related('conversation')
           