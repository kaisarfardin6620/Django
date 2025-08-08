import re
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, OTP, EmailVerificationToken, EmailChangeToken, UserActivityLog, PasswordHistory
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode
from django.utils import timezone
import requests
import hashlib
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

# Serializer for UserActivityLog
class UserActivityLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserActivityLog
        fields = ['activity_type', 'timestamp', 'ip_address', 'details']

# Custom Password Validators
def validate_strong_password(value):
    if len(value) < 8:
        raise serializers.ValidationError("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', value):
        raise serializers.ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', value):
        raise serializers.ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r'[0-9]', value):
        raise serializers.ValidationError("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(){}[\]<>?/|\-+=_]', value):
        raise serializers.ValidationError("Password must contain at least one special character: !@#$%^&*(){}[].")

def check_breached_password(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
        return suffix in response.text
    except requests.RequestException:
        return False

# Serializers
class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_strong_password])
    confirm_password = serializers.CharField(write_only=True)
    is_active = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'confirm_password', 'is_active']

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError("An account with this email address already exists.")
        if check_breached_password(data['password']):
            raise serializers.ValidationError("This password has been breached.")
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            is_active=False
        )
        return user

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        user = authenticate(username=attrs.get('username'), password=attrs.get('password'))
        if not user:
            raise serializers.ValidationError("Invalid username or password.")
        if not user.is_active:
            raise serializers.ValidationError("Email address not verified. Please check your inbox.")
        if user.userprofile.is_2fa_enabled:
            raise serializers.ValidationError("2FA is enabled. Please provide OTP.")
        attrs['user'] = user
        return attrs

class UserProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = UserProfile
        fields = ['username', 'email', 'is_2fa_enabled', 'profile_picture', 'date_of_birth', 'age', 'first_name', 'last_name', 'gender', 'bio', 'phone_number',   'failed_login_attempts', 'lockout_until', 'last_failed_login_ip']

class ProfilePictureUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['profile_picture']

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True, validators=[validate_strong_password])
    confirm_new_password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        user = self.context['request'].user
        if not user.check_password(data.get('old_password')):
            raise serializers.ValidationError({'old_password': 'Wrong password.'})
        if data.get('new_password') != data.get('new_password'):
            raise serializers.ValidationError({'new_password': 'New passwords must match.'})
        if user.check_password(data.get('new_password')):
            raise serializers.ValidationError({'new_password': 'New password cannot be the same as the old password.'})
        if check_breached_password(data.get('new_password')):
            raise serializers.ValidationError({'new_password': 'This password has been breached.'})
        password_history = PasswordHistory.objects.filter(user=user).order_by('-created_at')[:5]
        for history in password_history:
            if check_password(data.get('new_password'), history.hashed_password):
                raise serializers.ValidationError({'new_password': 'You cannot reuse one of your last 5 passwords.'})
        return data

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user found with this email address.")
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, validators=[validate_strong_password])
    confirm_password = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError("Passwords do not match.")
        if check_breached_password(data['password']):
            raise serializers.ValidationError("This password has been breached.")
        try:
            uid = force_str(urlsafe_base64_decode(data['uidb64']))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist, DjangoUnicodeDecodeError):
            raise serializers.ValidationError('Invalid password reset link.')
        if not PasswordResetTokenGenerator().check_token(user, data['token']):
            raise serializers.ValidationError('Invalid password reset link.')
        data['user'] = user
        return data

class OTPVerificationSerializer(serializers.Serializer):
    # Used for both signup verification and 2FA
    otp = serializers.CharField(required=True, max_length=6)

    def validate_otp(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("OTP must be numeric.")
        try:
            otp_obj = OTP.objects.get(code=value, is_used=False)
            if not otp_obj.is_valid():
                raise serializers.ValidationError("Invalid or expired OTP.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")
        return value

class AccountDeactivateSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, write_only=True)

    def validate_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Incorrect password.")
        return value

class AccountDeleteSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, write_only=True)

    def validate_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Incorrect password.")
        return value

class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.UUIDField()

    def validate_token(self, value):
        try:
            token_obj = EmailVerificationToken.objects.get(token=value)
            if not token_obj.is_valid():
                raise serializers.ValidationError("Invalid or expired token.")
        except EmailVerificationToken.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired token.")
        return value

class EmailChangeRequestSerializer(serializers.Serializer):
    new_email = serializers.EmailField(required=True)

    def validate_new_email(self, value):
        user = self.context.get('user')
        if not user:
            raise serializers.ValidationError("User context not provided.")
        if user.email == value:
            raise serializers.ValidationError("The new email address is the same as the current one.")
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("An account with this email address already exists.")
        return value

class EmailChangeConfirmSerializer(serializers.Serializer):
    token = serializers.UUIDField(required=True)

    def validate(self, data):
        try:
            token_obj = EmailChangeToken.objects.get(token=data['token'])
        except EmailChangeToken.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired email change token.")
        if not token_obj.is_valid():
            raise serializers.ValidationError("Invalid or expired email change token.")
        if token_obj.user.email == token_obj.new_email:
            raise serializers.ValidationError("Email is already set to the new email address.")
        self.token_obj = token_obj
        return data

    def save(self, **kwargs):
        token_obj = self.token_obj
        user = token_obj.user
        user.email = token_obj.new_email
        user.save()
        token_obj.delete()
        return user

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        return token