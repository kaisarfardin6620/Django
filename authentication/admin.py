from django.contrib import admin
from django.contrib.auth.models import User
from django.utils.html import format_html
from .models import UserProfile, OTP, EmailVerificationToken, UserActivityLog, EmailChangeToken, PasswordHistory

# Register the UserProfile model
@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'profile_picture_preview', 'date_of_birth', 'age', 'gender', 'phone_number', 'is_2fa_enabled', 'failed_login_attempts', 'lockout_until', 'last_failed_login_ip']
    search_fields = ['user__username', 'phone_number', 'id']
    list_filter = ['gender', 'is_2fa_enabled']
    readonly_fields = ['failed_login_attempts', 'lockout_until', 'last_failed_login_ip', 'profile_picture_preview']

    def profile_picture_preview(self, obj):
        if obj.profile_picture:
            return format_html('<img src="{}" style="max-height: 100px;" />', obj.profile_picture.url)
        return "No Image"
    profile_picture_preview.short_description = 'Profile Picture'

    # Override get_queryset to exclude staff users from UserProfile list
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.filter(user__is_staff=False)

# Register the OTP model
@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ['user', 'code', 'purpose', 'is_used', 'created_at']
    list_filter = ['purpose', 'is_used']
    search_fields = ['user__username', 'code']

# Register the EmailVerificationToken model
@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'token', 'created_at', 'expires_at', 'is_valid']
    search_fields = ['user__username', 'token']
    list_filter = ['created_at', 'expires_at']

# Register the UserActivityLog model
@admin.register(UserActivityLog)
class UserActivityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'timestamp', 'activity_type', 'ip_address')
    list_filter = ('activity_type', 'user')
    search_fields = ('user__username', 'activity_type')
    readonly_fields = ('user', 'timestamp', 'activity_type', 'ip_address', 'user_agent', 'details')

# Register the EmailChangeToken model
@admin.register(EmailChangeToken)
class EmailChangeTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'new_email', 'token', 'created_at', 'expires_at', 'is_valid']
    search_fields = ['user__username', 'new_email', 'token']
    list_filter = ['created_at', 'expires_at']

# Register the PasswordHistory model
@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'hashed_password', 'created_at')
    list_filter = ('user', 'created_at')
    search_fields = ('user__username',)
    readonly_fields = ('created_at',)