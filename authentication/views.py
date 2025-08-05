import random
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model, authenticate, login, logout
from django.core.mail import send_mail
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.utils import timezone
import uuid
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle 

from .models import UserProfile, OTP, EmailVerificationToken, UserActivityLog, EmailChangeToken, PasswordHistory 
from .serializers import (
    UserSignupSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserProfileNestedSerializer,
    PasswordChangeSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    OTPVerificationSerializer,
    AccountDeactivateSerializer,
    AccountDeleteSerializer,
    EmailVerificationSerializer,
    ProfilePictureUploadSerializer, 
    EmailChangeRequestSerializer, 
    EmailChangeConfirmSerializer 
)

User = get_user_model()

# Helper function to log user activity
def log_user_activity(user, action, request=None, details=None):
    ip_address = request.META.get('REMOTE_ADDR') if request else None
    user_agent = request.META.get('HTTP_USER_AGENT') if request else None
    UserActivityLog.objects.create(
        user=user,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details
    )

# Helper function to send OTP email
def send_otp_email(user, purpose):
    otp_code = str(random.randint(100000, 999999))
    OTP.objects.filter(user=user, purpose=purpose, is_used=False).update(is_used=True) # Invalidate old OTPs for this purpose
    OTP.objects.create(user=user, code=otp_code, purpose=purpose)
    
    subject = f'Your {purpose} verification code'
    message = f'Your one-time password for {purpose} is: {otp_code}. It is valid for 5 minutes.'
    send_mail(subject, message, 'a.kaisarfardin29@gmail.com', [user.email], fail_silently=False)

# Helper function to send email verification link for signup
def send_signup_verification_link(user):
    EmailVerificationToken.objects.filter(user=user).delete() # Invalidate any old tokens
    token_obj = EmailVerificationToken.objects.create(user=user)
    
    # IMPORTANT: Replace 'http://127.0.0.1:8001' with your actual Django server base URL for testing
    verification_url = f"http://127.0.0.1:8001/auth/verify-email/?token={token_obj.token}"
    
    subject = 'Verify Your Email Address'
    message = (f'Hi {user.username},\n\n'
               f'Thank you for signing up! Please click the link below to verify your email address:\n\n'
               f'{verification_url}\n\n'
               f'This link will expire in 24 hours.')
    send_mail(subject, message, 'a.kaisarfardin29@gmail.com', [user.email], fail_silently=False)

# Helper function to send email change verification link
def send_email_change_verification_link(user, new_email):
    EmailChangeToken.objects.filter(user=user).delete() # Invalidate any old tokens
    token_obj = EmailChangeToken.objects.create(user=user, new_email=new_email)
    
    # IMPORTANT: Replace 'http://127.0.0.1:8001' with your actual Django server base URL for testing
    verification_url = f"http://127.0.0.1:8001/auth/email/change/confirm/?token={token_obj.token}"
    
    subject = 'Confirm Your Email Change'
    message = (f'Hi {user.username},\n\n'
               f'You recently requested to change your email to {new_email}. '
               f'Please click the link below to confirm this change:\n\n'
               f'{verification_url}\n\n'
               f'This link will expire in 24 hours.')
    send_mail(subject, message, 'a.kaisarfardin29@gmail.com', [new_email], fail_silently=False)

# NEW: Helper function to send account lockout notification
def send_account_lockout_notification(user, lockout_duration_minutes):
    subject = 'Your Account Has Been Locked Due to Multiple Failed Login Attempts'
    message = (f'Hi {user.username},\n\n'
               f'Your account has been temporarily locked due to too many failed login attempts. '
               f'For security reasons, you will be unable to log in for the next {lockout_duration_minutes} minutes.\n\n'
               f'If you did not attempt to log in, please consider changing your password immediately '
               f'after the lockout period ends or contact support.')
    send_mail(subject, message, 'a.kaisarfardin29@gmail.com', [user.email], fail_silently=False)


class UserSignupAPIView(APIView):
    throttle_classes = [AnonRateThrottle] # Apply throttling
    def post(self, request, *args, **kwargs):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # --- CHOOSE ONE FOR SIGNUP VERIFICATION ---
            send_signup_verification_link(user) # Option 1: Email Link (Recommended for initial signup)
            # send_otp_email(user, 'signup') # Option 2: OTP (Uncomment this and comment above if you prefer OTP for signup)
            # --- END CHOOSE ONE ---

            log_user_activity(user, 'Signup Attempt', request=request, details='User registered, awaiting verification.')
            return Response({'message': 'User registered. Please check your email for a verification link to activate your account.'}, status=status.HTTP_201_CREATED)
        log_user_activity(None, 'Signup Failed', request=request, details=f'Errors: {serializer.errors}')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# Keep VerifySignupOTPView and ResendSignupOTPView if you choose OTP for signup
# Otherwise, these can be removed if you exclusively use email links for signup.
class VerifySignupOTPView(APIView):
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']
            
            try:
                user = User.objects.get(email=email)
                otp_entry = OTP.objects.filter(user=user, purpose='signup').last()

                if otp_entry and otp_entry.is_valid() and otp_entry.code == otp_code:
                    user.is_active = True
                    user.save()
                    otp_entry.is_used = True
                    otp_entry.save()
                    log_user_activity(user, 'Signup OTP Verified', request=request)
                    return Response({'message': 'Account activated successfully. You can now log in.'}, status=status.HTTP_200_OK)
                else:
                    log_user_activity(user, 'Signup OTP Failed', request=request, details='Invalid or expired OTP')
                    return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

            except User.DoesNotExist:
                log_user_activity(None, 'Signup OTP Failed', request=request, details=f'User not found for email: {email}')
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 
    

class ResendSignupOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
            if user.is_active:
                return Response({'message': 'Account is already active. Please log in.'}, status=status.HTTP_400_BAD_REQUEST)
            send_otp_email(user, 'signup')
            log_user_activity(user, 'Resend Signup OTP', request=request)
            return Response({'message': 'New OTP sent to your email.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)    

# New View to verify email link for signup
class VerifyEmailLinkAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            # Access the stored token_obj from serializer's validated_data
            token_obj = serializer.validated_data['token_obj'] 
            
            user = token_obj.user
            if user.is_active:
                return Response({'message': 'Account is already active.'}, status=status.HTTP_200_OK)
            
            user.is_active = True
            user.save()
            token_obj.delete() # Token used, delete it
            log_user_activity(user, 'Email Verified & Account Activated', request=request)
            return Response({'message': 'Email verified and account activated successfully. You can now log in.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# New View to resend email verification link for signup
class ResendVerificationLinkAPIView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        
        if user.is_active:
            return Response({'message': 'Account is already active. Please log in.'}, status=status.HTTP_400_BAD_REQUEST)
        
        send_signup_verification_link(user)
        log_user_activity(user, 'Resend Email Verification Link', request=request)
        return Response({'message': 'New verification link sent to your email.'}, status=status.HTTP_200_OK)


class UserLoginAPIView(APIView):
    throttle_classes = [AnonRateThrottle] # Apply throttling
    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user'] # Get user from serializer's validated_data
            password = request.data.get('password') # Get password directly from request.data

            # Account Lockout Check
            if user.userprofile.lockout_until and user.userprofile.lockout_until > timezone.now():
                remaining_time = int((user.userprofile.lockout_until - timezone.now()).total_seconds() / 60)
                log_user_activity(user, 'Login Failed', request=request, details=f'Account locked for {remaining_time} minutes.')
                return Response({'error': f'Account locked. Please try again in {remaining_time} minutes.'}, status=status.HTTP_403_FORBIDDEN)

            # Manually check password for potentially inactive user
            if user.check_password(password):
                # If the user was inactive, reactivate them here
                if not user.is_active:
                    user.is_active = True
                    user.save()
                    log_user_activity(user, 'Account Reactivated via Login', request=request)
                
                # Reset failed login attempts on successful login (or reactivation)
                user.userprofile.failed_login_attempts = 0
                user.userprofile.lockout_until = None
                # NEW: Clear last_failed_login_ip on successful login
                user.userprofile.last_failed_login_ip = None 
                user.userprofile.save()

                # Now authenticate and log in the user
                authenticated_user = authenticate(request, username=user.username, password=password) # Use user.username for authenticate

                if authenticated_user and authenticated_user.userprofile.is_2fa_enabled:
                    request.session['pre_2fa_user_id'] = authenticated_user.id
                    send_otp_email(authenticated_user, '2fa')
                    log_user_activity(authenticated_user, 'Login Attempt - 2FA Required', request=request)
                    return Response({'message': '2FA enabled. Please check your email for the verification code.'}, status=status.HTTP_200_OK)
                elif authenticated_user: # User is active and 2FA is not enabled
                    login(request, authenticated_user)
                    log_user_activity(authenticated_user, 'Login Success', request=request)
                    return Response({'message': 'User logged in successfully'}, status=status.HTTP_200_OK)
                else: # Should ideally not happen if password check passed and user.is_active is True
                    log_user_activity(user, 'Login Failed', request=request, details='Authentication failed after password check (unexpected).')
                    return Response({'error': 'Invalid credentials (authentication failed)'}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                # Increment failed login attempts
                user.userprofile.failed_login_attempts += 1
                # NEW: Store the IP of the failed attempt
                user.userprofile.last_failed_login_ip = request.META.get('REMOTE_ADDR')
                
                # Escalating lockout durations
                lockout_duration_minutes = 0
                if user.userprofile.failed_login_attempts >= 15: # e.g., 15 attempts -> 60 min lockout
                    lockout_duration_minutes = 60
                elif user.userprofile.failed_login_attempts >= 10: # e.g., 10 attempts -> 30 min lockout
                    lockout_duration_minutes = 30
                elif user.userprofile.failed_login_attempts >= 5: # e.g., 5 attempts -> 15 min lockout
                    lockout_duration_minutes = 15
                
                if lockout_duration_minutes > 0:
                    user.userprofile.lockout_until = timezone.now() + timezone.timedelta(minutes=lockout_duration_minutes)
                    log_user_activity(user, 'Account Locked', request=request, details=f'Too many failed login attempts. Locked for {lockout_duration_minutes} minutes from IP: {user.userprofile.last_failed_login_ip}.')
                    send_account_lockout_notification(user, lockout_duration_minutes) # Send notification
                    return Response({'error': f'Too many failed login attempts. Account locked for {lockout_duration_minutes} minutes.'}, status=status.HTTP_403_FORBIDDEN)
                
                user.userprofile.save()
                log_user_activity(user, 'Login Failed', request=request, details=f'Invalid credentials from IP: {request.META.get("REMOTE_ADDR")}. Attempts: {user.userprofile.failed_login_attempts}.')
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        log_user_activity(None, 'Login Failed', request=request, details=f'Serializer errors: {serializer.errors}')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class Verify2FAOTPView(APIView):
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']
            
            pre_2fa_user_id = request.session.get('pre_2fa_user_id')
            if not pre_2fa_user_id:
                log_user_activity(None, '2FA Verification Failed', request=request, details='Session expired or invalid login attempt.')
                return Response({'error': 'Session expired or invalid login attempt'}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                user = User.objects.get(id=pre_2fa_user_id, email=email)
                otp_entry = OTP.objects.filter(user=user, purpose='2fa').last()

                if otp_entry and otp_entry.is_valid() and otp_entry.code == otp_code:
                    otp_entry.is_used = True
                    otp_entry.save()
                    
                    login(request, user)
                    del request.session['pre_2fa_user_id']
                    log_user_activity(user, '2FA Verified & Login Success', request=request)
                    return Response({'message': 'Login successful with 2FA'}, status=status.HTTP_200_OK)
                else:
                    log_user_activity(user, '2FA Verification Failed', request=request, details='Invalid or expired OTP.')
                    return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

            except User.DoesNotExist:
                log_user_activity(None, '2FA Verification Failed', request=request, details=f'User not found for email: {email}')
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    
    

class Resend2FAOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
            if not user.userprofile.is_2fa_enabled:
                 return Response({'error': '2FA is not enabled for this account.'}, status=status.HTTP_400_BAD_REQUEST)
            
            if user.id != request.session.get('pre_2fa_user_id'):
                return Response({'error': 'Unauthorized request'}, status=status.HTTP_401_UNAUTHORIZED)

            send_otp_email(user, '2fa')
            log_user_activity(user, 'Resend 2FA OTP', request=request)
            return Response({'message': 'New OTP sent to your email.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class UserLogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, *args, **kwargs):
        log_user_activity(request.user, 'Logout Success', request=request)
        logout(request)
        return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)

class UserProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        serializer = UserProfileSerializer(request.user)
        log_user_activity(request.user, 'View Profile', request=request)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UpdateProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, *args, **kwargs):
        try:
            profile = request.user.userprofile
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserProfileNestedSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            log_user_activity(request.user, 'Profile Updated', request=request, details=f'Fields: {list(request.data.keys())}')
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# New View for Profile Picture Upload
class ProfilePictureUploadAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        try:
            profile = request.user.userprofile
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Use ProfilePictureUploadSerializer which only handles the image field
        serializer = ProfilePictureUploadSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            log_user_activity(request.user, 'Profile Picture Uploaded', request=request)
            return Response({'message': 'Profile picture updated successfully.', 'profile_picture_url': profile.profile_picture.url}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, *args, **kwargs):
        user = request.user
        # Pass the request context to the serializer
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            old_password = serializer.validated_data.get('old_password')
            new_password = serializer.validated_data.get('new_password')
            
            # This check is crucial and correctly placed here in the view
            if not user.check_password(old_password):
                log_user_activity(user, 'Password Change Failed', request=request, details='Incorrect old password.')
                return Response({'old_password': ['Incorrect old password']}, status=status.HTTP_400_BAD_REQUEST)
            
            user.set_password(new_password)
            user.save()
            # Save new password to history
            PasswordHistory.objects.create(user=user, hashed_password=user.password)
            log_user_activity(user, 'Password Changed', request=request)
            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        log_user_activity(user, 'Password Change Failed', request=request, details=f'Errors: {serializer.errors}')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestAPIView(APIView):
    throttle_classes = [AnonRateThrottle] # Apply throttling
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            try:
                if serializer.validated_data.get('email'):
                    user = User.objects.get(email=serializer.validated_data['email'])
                else:
                    user = User.objects.get(username=serializer.validated_data['username'])
            except User.DoesNotExist:
                # To prevent username enumeration, send a success message even if user doesn't exist
                log_user_activity(None, 'Password Reset Request', request=request, details='User not found, but success message sent to prevent enumeration.')
                return Response({'message': 'If an account with that email/username exists, a password reset link has been sent.'}, status=status.HTTP_200_OK)

            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # IMPORTANT: Replace 'http://127.0.0.1:8001' with your actual Django server base URL for testing
            reset_url = f"http://127.0.0.1:8001/auth/password/reset/confirm/?uid={uid}&token={token}"

            subject = 'Password Reset Requested'
            message = (f'Hi {user.username},\n\n'
                       f'Please use the following link to reset your password:\n\n'
                       f'{reset_url}\n\n'
                       f'This link will expire in 24 hours.')
            send_mail(subject, message, 'a.kaisarfardin29@gmail.com', [user.email], fail_silently=False)
            
            log_user_activity(user, 'Password Reset Link Sent', request=request)
            return Response({'message': 'If an account with that email/username exists, a password reset link has been sent.'}, status=status.HTTP_200_OK)
        log_user_activity(None, 'Password Reset Request Failed', request=request, details=f'Errors: {serializer.errors}')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class PasswordResetConfirmAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            # The serializer's validate method should have already set self.user
            user = serializer.user 
            new_password = serializer.validated_data['new_password']
            user.set_password(new_password)
            user.save()
            # Save new password to history
            PasswordHistory.objects.create(user=user, hashed_password=user.password)
            log_user_activity(user, 'Password Reset Confirmed', request=request)
            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        log_user_activity(None, 'Password Reset Confirmation Failed', request=request, details=f'Errors: {serializer.errors}')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Toggle2FAAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, *args, **kwargs):
        user = request.user
        
        user_profile = user.userprofile
        user_profile.is_2fa_enabled = not user_profile.is_2fa_enabled
        user_profile.save()

        status_message = "enabled" if user_profile.is_2fa_enabled else "disabled"
        log_user_activity(user, f'2FA {status_message.capitalize()}', request=request)
        return Response({'message': f'Two-Factor Authentication has been {status_message}.'}, status=status.HTTP_200_OK)


class DeactivateAccountAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        serializer = AccountDeactivateSerializer(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data.get('password')
            if not user.check_password(password):
                log_user_activity(user, 'Account Deactivation Failed', request=request, details='Incorrect password.')
                return Response({'password': ['Incorrect password']}, status=status.HTTP_400_BAD_REQUEST)

            user.is_active = False
            user.save()
            logout(request)
            log_user_activity(user, 'Account Deactivated', request=request)
            return Response({'message': 'Account deactivated successfully. You have been logged out.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteAccountAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        serializer = AccountDeleteSerializer(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data.get('password')
            if not user.check_password(password):
                log_user_activity(user, 'Account Deletion Failed', request=request, details='Incorrect password.')
                return Response({'password': ['Incorrect password']}, status=status.HTTP_400_BAD_REQUEST)

            log_user_activity(user, 'Account Deleted', request=request, details='Account and associated data permanently removed.')
            user.delete() # This will also delete the associated UserProfile due to CASCADE
            logout(request)

            return Response({'message': 'Account deleted successfully. You have been logged out.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ReactivateAccountAPIView is removed as login now handles reactivation
# This view is no longer needed and is fully removed.

class UserActivityLogAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        logs = UserActivityLog.objects.filter(user=request.user).order_by('-timestamp')
        # You might want to paginate this in a real app
        data = [{'timestamp': log.timestamp, 'action': log.action, 'ip_address': log.ip_address, 'user_agent': log.user_agent, 'details': log.details} for log in logs]
        log_user_activity(request.user, 'View Activity Log', request=request)
        return Response(data, status=status.HTTP_200_OK)

# New View for Email Change Request
class EmailChangeRequestAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = EmailChangeRequestSerializer(data=request.data)
        if serializer.is_valid():
            new_email = serializer.validated_data['new_email']
            user = request.user

            if user.email == new_email:
                return Response({'message': 'New email is the same as current email.'}, status=status.HTTP_400_BAD_REQUEST)
            
            send_email_change_verification_link(user, new_email)
            log_user_activity(user, 'Email Change Request', request=request, details=f'Requested change to: {new_email}')
            return Response({'message': 'Verification link sent to your new email address. Please check your inbox to confirm the change.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# New View for Email Change Confirmation
class EmailChangeConfirmAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = EmailChangeConfirmSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save() # Serializer's save method updates user email and deletes token
            log_user_activity(user, 'Email Changed Confirmed', request=request, details=f'Email updated to: {user.email}')
            return Response({'message': 'Email address updated successfully.'}, status=status.HTTP_200_OK)
        log_user_activity(None, 'Email Change Confirmation Failed', request=request, details=f'Errors: {serializer.errors}')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
