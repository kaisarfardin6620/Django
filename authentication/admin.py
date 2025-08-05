from django.contrib import admin
from django.contrib.auth.models import User
# Removed: from django.contrib.auth.admin import UserAdmin # No longer needed if using default UserAdmin
from .models import UserProfile, OTP, EmailVerificationToken, UserActivityLog, EmailChangeToken, PasswordHistory

# Register the UserProfile model
@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'date_of_birth', 'age', 'gender', 'phone_number', 'is_2fa_enabled', 'failed_login_attempts', 'lockout_until',  'last_failed_login_ip']
    search_fields = ['user__username', 'phone_number', 'id']
    list_filter = ['gender', 'is_2fa_enabled']
    readonly_fields = ['failed_login_attempts', 'lockout_until', 'last_failed_login_ip']

    # Override get_queryset to exclude staff users from UserProfile list
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # Exclude users who are staff (e.g., admin users)
        return qs.filter(user__is_staff=False)


# Register the new OTP model
@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'code', 'purpose', 'is_used', 'created_at']
    list_filter = ['purpose', 'is_used']
    search_fields = ['user__username', 'code']

# Register the EmailVerificationToken model
@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'token', 'created_at', 'expires_at', 'is_valid']
    search_fields = ['user__username', 'token']
    list_filter = ['created_at', 'expires_at']

# Register the UserActivityLog model
@admin.register(UserActivityLog)
class UserActivityLogAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'action', 'timestamp', 'ip_address']
    list_filter = ['action', 'timestamp']
    search_fields = ['user__username', 'action', 'ip_address', 'details']
    readonly_fields = ['user', 'timestamp', 'action', 'ip_address', 'user_agent', 'details']

# Register the EmailChangeToken model
@admin.register(EmailChangeToken)
class EmailChangeTokenAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'new_email', 'token', 'created_at', 'expires_at', 'is_valid']
    search_fields = ['user__username', 'new_email', 'token']
    list_filter = ['created_at', 'expires_at']

# Register the PasswordHistory model
@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'created_at', 'hashed_password']
    list_filter = ['created_at']
    search_fields = ['user__username']
    readonly_fields = ['user', 'created_at', 'hashed_password']


# Removed: CustomUserAdmin class and unregister/register lines for User
# This means Django will use its default UserAdmin for the User model.
# class CustomUserAdmin(UserAdmin):
#     list_display = ('id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active') 

# admin.site.unregister(User)
# admin.site.register(User, CustomUserAdmin)
