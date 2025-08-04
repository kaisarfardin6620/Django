from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid # Import uuid for unique tokens

# Define a named function for the default expires_at value
def default_expires_at():
    return timezone.now() + timezone.timedelta(days=1)

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    password = models.CharField(max_length=100, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)
    age = models.PositiveIntegerField(null=True, blank=True)
    gender = models.CharField(max_length=10, blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_2fa_enabled = models.BooleanField(default=False)
    # Fields for Account Lockout
    failed_login_attempts = models.PositiveIntegerField(default=0)
    lockout_until = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.user.username


class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    purpose = models.CharField(max_length=20)  # e.g., 'signup', '2fa', 'email_change'
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def is_valid(self):
        """Checks if the OTP is not used and is within a valid time window (e.g., 5 minutes)."""
        # OTPs are valid for 5 minutes (300 seconds)
        return not self.is_used and (timezone.now() - self.created_at).seconds < 300

    def __str__(self):
        return f"{self.user.username} - {self.purpose} - {self.code}"


class EmailVerificationToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # Tokens are valid for 24 hours (86400 seconds)
    expires_at = models.DateTimeField(default=default_expires_at) 

    def is_valid(self):
        """Checks if the token has not expired."""
        return timezone.now() < self.expires_at

    def __str__(self):
        return f"Verification token for {self.user.username}"


class UserActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    action = models.CharField(max_length=255) # e.g., 'Login Success', 'Login Failed', 'Password Change', '2FA Enabled'
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    details = models.TextField(null=True, blank=True) # Additional details like 'reason for failed login'

    def __str__(self):
        return f"{self.user.username if self.user else 'Anonymous'} - {self.action} at {self.timestamp.strftime('%Y-%m-%d %H:%M')}"

    class Meta:
        ordering = ['-timestamp'] # Order by most recent first

# New model for Email Change Verification
class EmailChangeToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    new_email = models.EmailField()
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=default_expires_at) # Reusing the 24-hour expiry

    def is_valid(self):
        return timezone.now() < self.expires_at

    def __str__(self):
        return f"Email change token for {self.user.username} to {self.new_email}"
