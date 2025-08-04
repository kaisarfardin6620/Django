from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin
from .models import UserProfile, OTP, EmailVerificationToken, UserActivityLog, EmailChangeToken # Import new models

# Register the UserProfile model
@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'date_of_birth', 'age', 'gender', 'phone_number', 'is_2fa_enabled', 'failed_login_attempts', 'lockout_until', 'id']
    search_fields = ['user__username', 'phone_number', 'id']
    list_filter = ['gender', 'is_2fa_enabled']
    readonly_fields = ['failed_login_attempts', 'lockout_until'] # Make these read-only in admin

# Register the new OTP model
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

# Register the UserActivityLog model (NEW)
@admin.register(UserActivityLog)
class UserActivityLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'timestamp', 'ip_address']
    list_filter = ['action', 'timestamp']
    search_fields = ['user__username', 'action', 'ip_address', 'details']
    readonly_fields = ['user', 'timestamp', 'action', 'ip_address', 'user_agent', 'details'] # Make all fields read-only

# Register the EmailChangeToken model (NEW)
@admin.register(EmailChangeToken)
class EmailChangeTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'new_email', 'token', 'created_at', 'expires_at', 'is_valid']
    search_fields = ['user__username', 'new_email', 'token']
    list_filter = ['created_at', 'expires_at']


# Customize the User admin
class CustomUserAdmin(UserAdmin):
    list_display = ('id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active') 

admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
