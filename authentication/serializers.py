import re
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, OTP, EmailVerificationToken, EmailChangeToken, UserActivityLog # Ensure all models are imported
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils import timezone # Import timezone for custom validation

# Custom password validation function
def validate_strong_password(value):
    if len(value) < 8:
        raise serializers.ValidationError("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', value):
        raise serializers.ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', value):
        raise serializers.ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r'[0-9]', value):
        raise serializers.ValidationError("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
        raise serializers.ValidationError("Password must contain at least one special character.")
    return value

class UserSignupSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True, 'validators': [validate_strong_password]} # Apply password strength validation
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            is_active=False # User is inactive until email link is verified
        )
        UserProfile.objects.create(user=user)
        return user

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

class UserProfileSerializer(serializers.ModelSerializer):
    profile = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'date_joined', 'profile']

    def get_profile(self, user):
        try:
            profile = user.userprofile
            return UserProfileNestedSerializer(profile).data
        except UserProfile.DoesNotExist:
            return None

class UserProfileNestedSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['id', 'date_of_birth', 'profile_picture', 'age', 'gender', 'phone_number', 'address', 'updated_at', 'is_2fa_enabled'] # Added is_2fa_enabled to profile

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_strong_password]) # Apply password strength validation
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "New passwords must match."})
        return data

class PasswordResetRequestSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)

    def validate(self, data):
        if not data.get('username') and not data.get('email'):
            raise serializers.ValidationError("Either username or email is required")
        return data

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_strong_password]) # Apply password strength validation
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "New passwords must match."})
        
        try:
            uid = force_str(data.get('uid'))
            user = User.objects.get(pk=uid)
            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(user, data.get('token')):
                raise serializers.ValidationError("Invalid or expired password reset token.")
            self.user = user # Store user for use in save method
        except (User.DoesNotExist, TypeError, ValueError, OverflowError):
            raise serializers.ValidationError("Invalid or expired password reset token.")
        
        return data

    def save(self, **kwargs):
        user = self.user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp_code = serializers.CharField(required=True, max_length=6)
    
class AccountDeactivateSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)

class AccountDeleteSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)

class AccountReactivateSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.UUIDField(required=True)

# New serializer for Profile Picture Upload
class ProfilePictureUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['profile_picture']
        read_only_fields = ['id', 'user'] # Ensure only profile_picture can be updated

# New serializer for Email Change Request
class EmailChangeRequestSerializer(serializers.Serializer):
    new_email = serializers.EmailField(required=True)

    def validate_new_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is already in use.")
        return value

# New serializer for Email Change Confirmation
class EmailChangeConfirmSerializer(serializers.Serializer):
    token = serializers.UUIDField(required=True)
    # The new_email is implicitly handled by the token, but can be added for clarity if needed
    # new_email = serializers.EmailField(required=True) 

    def validate(self, data):
        try:
            token_obj = EmailChangeToken.objects.get(token=data['token'])
        except EmailChangeToken.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired email change token.")

        if not token_obj.is_valid():
            raise serializers.ValidationError("Invalid or expired email change token.")
        
        if token_obj.user.email == token_obj.new_email:
            raise serializers.ValidationError("Email is already set to the new email address.")

        self.token_obj = token_obj # Store token_obj for use in save method
        return data

    def save(self, **kwargs):
        token_obj = self.token_obj
        user = token_obj.user
        user.email = token_obj.new_email
        user.save()
        token_obj.delete() # Invalidate token after use
        return user
