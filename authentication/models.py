from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import RegexValidator
import uuid

class UserProfile(models.Model):
    GENDER_CHOICES = (
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
    )
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, blank=True, null=True)
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        validators=[
            RegexValidator(
                regex=r"^\+?[1-9]\d{1,14}$",
                message="Phone number must be in E.164 format: '+1234567890'"
            )
        ]
    )
    is_2fa_enabled = models.BooleanField(default=False)
    failed_login_attempts = models.IntegerField(default=0)
    lockout_until = models.DateTimeField(null=True, blank=True)
    last_failed_login_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def age(self):
        if self.date_of_birth:
            today = timezone.now().date()
            return today.year - self.date_of_birth.year - (
                (today.month, today.day) < 
                (self.date_of_birth.month, self.date_of_birth.day)
            )
        return None

class AuthToken(models.Model):
    TOKEN_TYPES = (
        ('signup', 'Signup Verification'),
        ('2fa', 'Two-Factor Authentication'),
        ('password_reset', 'Password Reset'),
        ('email_change', 'Email Change'),
        ('reactivation', 'Account Reactivation'),
        ('email_verification', 'Email Verification'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='auth_tokens')
    token_type = models.CharField(max_length=20, choices=TOKEN_TYPES)
    new_email = models.EmailField(blank=True, null=True)  # For email change requests
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    otp_code = models.CharField(max_length=6, blank=True, null=True)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            if self.token_type in ['signup', '2fa']:
                self.expires_at = timezone.now() + timezone.timedelta(minutes=15)
            else:
                self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)

    def is_valid(self):
        return not self.is_used and self.expires_at > timezone.now()

class PasswordHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_history')
    hashed_password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Save the new password history
        super().save(*args, **kwargs)
        # Keep only last 10 passwords (delete oldest if more than 10)
        histories = PasswordHistory.objects.filter(user=self.user).order_by('-created_at')
        if histories.count() > 10:
            oldest = PasswordHistory.objects.filter(user=self.user).order_by('created_at').first()
            if oldest:
                oldest.delete()

class UserActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='activity_logs')
    activity_type = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(null=True, blank=True)
