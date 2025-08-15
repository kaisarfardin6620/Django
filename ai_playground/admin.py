from django.contrib import admin
from .models import AIPlayground, Conversation, Message, Attachment

class MessageInline(admin.TabularInline):
    model = Message
    fields = ('role','text','created_at')
    readonly_fields = ('created_at',)
    extra = 0

class AttachmentInline(admin.TabularInline):
    model = Attachment
    fields = ('attachment_type','file','filename','uploaded_by','created_at')
    readonly_fields = ('created_at',)
    extra = 0

@admin.register(AIPlayground)
class AIPlaygroundAdmin(admin.ModelAdmin):
    list_display = ('id','title','user','created_at','updated_at')
    search_fields = ('title','user__username')
    list_filter = ('created_at','updated_at')
    ordering = ('-created_at',)
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = ('id','title','playground_title','created_by_username','created_at','updated_at','is_archived')
    search_fields = ('title','playground__title','created_by__username')
    list_filter = ('created_at','updated_at','is_archived')
    ordering = ('-updated_at',)
    inlines = [MessageInline, AttachmentInline]

    @admin.display(description='Playground')
    def playground_title(self,obj):
        return obj.playground.title

    @admin.display(description='Created By')
    def created_by_username(self,obj):
        return obj.created_by.username

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('playground','created_by')

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id','conversation_title','role','text','created_at')
    search_fields = ('conversation__title','text')
    list_filter = ('role','created_at')
    ordering = ('-created_at',)
    @admin.display(description='Conversation')
    def conversation_title(self,obj):
        return obj.conversation.title
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('conversation')

@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    list_display = ('conversation_title','filename','attachment_type','created_at')
    search_fields = ('conversation__title','filename','attachment_type')
    list_filter = ('attachment_type','created_at')
    ordering = ('-created_at',)
    @admin.display(description='Conversation')
    def conversation_title(self,obj):
        return obj.conversation.title
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('conversation')
