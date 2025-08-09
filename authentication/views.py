from django.conf import settings
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password, make_password
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, BlacklistMixin
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import AuthToken, UserProfile, PasswordHistory, UserActivityLog
from .serializers import (
    SignupSerializer, LoginSerializer, OTPVerificationSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    ChangePasswordSerializer, ProfileSerializer, UpdateProfileSerializer,
    ProfilePictureSerializer, EmailChangeRequestSerializer,
    EmailChangeConfirmSerializer, ResendVerificationSerializer,
    MyTokenObtainPairSerializer,
    UserActivityLogSerializer,
    Verify2FALoginSerializer
)
import uuid
import random
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken

# Helper function to generate a 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Helper function to get the client's IP address
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# Helper function to send an email
def send_email(subject, message, recipient_list):
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            recipient_list,
            fail_silently=False,
        )
        return True
    except Exception as e:
        # Log the error for debugging
        print(f"Error sending email: {e}")
        return False

# Helper function to send the OTP email
def send_otp_email(user, otp):
    subject = 'Your OTP for account verification'
    message = f'Hi {user.username}, your One-Time Password (OTP) is: {otp}. It is valid for 15 minutes.'
    return send_email(subject, message, [user.email])

# Helper function to send a verification email link
def send_verification_email(user, token):
    subject = 'Account Verification'
    # NOTE: Ensure this URL matches a path in your urls.py file.
    # The URL should handle a GET request with a 'token' parameter.
    message = f'Hi {user.username}, please click the link to verify your account: http://127.0.0.1:8001/auth/verify-email/?token={token.token}'
    return send_email(subject, message, [user.email])

# View for user signup
class UserSignupAPIView(APIView):
    """
    Handles user signup and creates a related UserProfile.
    The verification method (OTP or email link) is determined by the
    USE_OTP_VERIFICATION setting.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Use getattr to safely check for the setting
            use_otp = getattr(settings, 'USE_OTP_VERIFICATION', False)

            if use_otp:
                # Generate a 6-digit OTP and save it in the new otp_code field.
                otp = generate_otp()
                AuthToken.objects.create(
                    user=user,
                    otp_code=otp,
                    token_type='signup_otp',
                )
                send_otp_email(user, otp)
                
                return Response(
                    {"message": "User registered successfully. An OTP has been sent to your email."},
                    status=status.HTTP_201_CREATED
                )
            else:
                # Generate a UUID token for email verification links.
                token = AuthToken.objects.create(
                    user=user,
                    token_type='signup_link',
                )
                send_verification_email(user, token)
                
                return Response(
                    {"message": "User registered successfully. A verification email has been sent."},
                    status=status.HTTP_201_CREATED
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# View for OTP verification during signup
class VerifySignupOTPView(APIView):
    """
    API view to handle OTP verification for signup.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            otp = serializer.validated_data['otp']
            
            # Use a more granular try-except block to provide better feedback
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response({'error': 'Invalid username.'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                token = AuthToken.objects.get(
                    user=user,
                    otp_code=otp,
                    token_type='signup_otp',
                    is_used=False
                )
            except AuthToken.DoesNotExist:
                return Response({'error': 'Invalid or expired OTP.'}, status=status.HTTP_400_BAD_REQUEST)

            # Check for token expiration separately to be more explicit
            if token.expires_at < timezone.now():
                token.is_used = True
                token.save()
                return Response({'error': 'OTP has expired.'}, status=status.HTTP_400_BAD_REQUEST)
            
            user.is_active = True
            user.save()

            token.is_used = True
            token.save()

            return Response(
                {'message': 'OTP verified successfully. Your account is now active.'},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResendSignupOTPView(APIView):
    """
    API view to resend OTP for signup verification.
    """
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = ResendVerificationSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            try:
                user = User.objects.get(username=username)
                if user.is_active:
                    return Response({'error': 'Account is already active.'}, status=status.HTTP_400_BAD_REQUEST)

                # Expire any existing OTP tokens
                AuthToken.objects.filter(user=user, token_type='signup_otp', is_used=False).update(expires_at=timezone.now())

                # Generate and send a new OTP
                otp = generate_otp()
                AuthToken.objects.create(
                    user=user,
                    otp_code=otp,
                    token_type='signup_otp',
                )
                send_otp_email(user, otp)
                
                return Response({'message': 'New OTP sent to your email.'}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# View for verifying email with a link
class VerifyEmailLinkAPIView(APIView):
    """
    API view to handle email verification via a link.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        token_uuid = request.GET.get('token')
        if not token_uuid:
            return Response({'error': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = AuthToken.objects.get(token=token_uuid, token_type='signup_link', is_used=False)
            
            if token.expires_at > timezone.now():
                user = token.user
                user.is_active = True
                user.save()
                token.is_used = True
                token.save()
                return Response(
                    {'message': 'Email verified successfully. Your account is now active.'},
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {'error': 'Token has expired.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        except AuthToken.DoesNotExist:
            return Response(
                {'error': 'Invalid token or token already used.'},
                status=status.HTTP_400_BAD_REQUEST
            )

# View to resend a verification link
class ResendVerificationLinkAPIView(APIView):
    """
    API view to resend a verification link.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResendVerificationSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            try:
                user = User.objects.get(username=username)
                if user.is_active:
                    return Response({'error': 'Account is already active.'}, status=status.HTTP_400_BAD_REQUEST)
                
                AuthToken.objects.filter(user=user, token_type='signup_link', is_used=False).update(expires_at=timezone.now())
                
                token = AuthToken.objects.create(user=user, token_type='signup_link')
                send_verification_email(user, token)
                return Response({'message': 'Verification email resent successfully.'}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# View for user login with a custom serializer that handles authentication
class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data

        # If user is inactive → Reactivation flow
        if not user.is_active:
            auth_token = AuthToken.objects.create(
                user=user,
                token_type='reactivation',
                expires_at=timezone.now() + timezone.timedelta(minutes=15)
            )

            if settings.USE_OTP_VERIFICATION:
                otp = str(random.randint(100000, 999999))
                auth_token.otp_code = otp
                auth_token.save()

                send_mail(
                    subject="Reactivate Your Account",
                    message=f"Your account reactivation code is: {otp}",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False
                )
            else:
                link = f"{settings.FRONTEND_URL}/reactivate-account?token={auth_token.token}"
                send_mail(
                    subject="Reactivate Your Account",
                    message=f"Click the following link to reactivate your account:\n{link}",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False
                )

            # Log reactivation attempt
            UserActivityLog.objects.create(
                user=user,
                activity_type='REACTIVATE_REQUEST',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            return Response({
                "reactivation_required": True,
                "message": "Reactivation email sent."
            }, status=status.HTTP_200_OK)

        # If user is active but 2FA is enabled → 2FA flow
        if hasattr(user, 'profile') and user.profile.is_2fa_enabled:
            auth_token = AuthToken.objects.create(
                user=user,
                token_type='2fa',
                expires_at=timezone.now() + timezone.timedelta(minutes=15)
            )

            if settings.USE_OTP_VERIFICATION:
                otp = str(random.randint(100000, 999999))
                auth_token.otp_code = otp
                auth_token.save()

                send_mail(
                    subject="Your 2FA OTP Code",
                    message=f"Your one-time login code is: {otp}",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False
                )
            else:
                link = f"{settings.FRONTEND_URL}/verify-2fa?token={auth_token.token}"
                send_mail(
                    subject="Verify Your Login",
                    message=f"Click the following link to verify your login:\n{link}",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False
                )

            # Log 2FA request
            UserActivityLog.objects.create(
                user=user,
                activity_type='2FA_REQUEST',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            return Response({
                "2fa_required": True,
                "message": "Verification sent to your email."
            }, status=status.HTTP_200_OK)

        # Normal login → issue JWT tokens immediately
        refresh = RefreshToken.for_user(user)

        # Log successful login
        UserActivityLog.objects.create(
            user=user,
            activity_type='LOGIN',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "username": user.username
        }, status=status.HTTP_200_OK)



class MyTokenObtainPairView(TokenObtainPairView):
    """
    Custom JWT view with activity logging and 2FA support.
    Modified to reactivate a user's account if they log in successfully
    while their account is inactive.
    """
    serializer_class = MyTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        # Attempt to get the user by username first, regardless of active status
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if the password is correct
        if not user.check_password(password):
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        # If the user is found and password is correct, check if they are inactive
        if not user.is_active:
            user.is_active = True
            user.save()
            
            # Log the reactivation event
            UserActivityLog.objects.create(
                user=user,
                activity_type='REACTIVATE',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            print(f"User {user.username} reactivated on login.")
            
        # Check if 2FA is enabled for the user (only after successful authentication)
        if getattr(user, 'profile', None) and user.profile.is_2fa_enabled:
            # Check for an existing, unused OTP token and expire it
            AuthToken.objects.filter(user=user, token_type='2fa_login', is_used=False).update(expires_at=timezone.now())

            # Generate and send a new OTP for login verification
            otp = generate_otp()
            AuthToken.objects.create(user=user, otp_code=otp, token_type='2fa_login')
            send_otp_email(user, otp)

            return Response(
                {"message": "2FA enabled. An OTP has been sent to your email. Please verify to log in."},
                status=status.HTTP_200_OK
            )
        else:
            # If no 2FA, proceed with normal login and token generation
            response = super().post(request, *args, **kwargs)
            if response.status_code == 200:
                # Log the login activity
                UserActivityLog.objects.create(
                    user=user,
                    activity_type='LOGIN',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
            return response

class Verify2FALoginView(APIView):
    def post(self, request):
        serializer = Verify2FALoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data['username']
        otp_or_token = serializer.validated_data['otp']

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"error": "Invalid username"}, status=status.HTTP_404_NOT_FOUND)

        # Detect whether this is reactivation or 2FA verification
        if settings.USE_OTP_VERIFICATION:
            token_obj = AuthToken.objects.filter(
                user=user,
                token_type__in=['2fa', 'reactivation'],
                otp_code=otp_or_token,
                is_used=False,
                expires_at__gt=timezone.now()
            ).first()
        else:
            token_obj = AuthToken.objects.filter(
                user=user,
                token_type__in=['2fa', 'reactivation'],
                token=otp_or_token,
                is_used=False,
                expires_at__gt=timezone.now()
            ).first()

        if not token_obj:
            return Response({"error": "Invalid or expired verification"}, status=status.HTTP_400_BAD_REQUEST)

        # Mark token as used
        token_obj.is_used = True
        token_obj.save()

        # If reactivation, activate the account
        if token_obj.token_type == 'reactivation':
            user.is_active = True
            user.save()

        # Issue JWT tokens
        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "username": user.username
        }, status=status.HTTP_200_OK)

class Resend2FAOTPView(APIView):
    """
    API view to resend 2FA OTP for login.
    """
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        if not getattr(user, 'profile', None) or not user.profile.is_2fa_enabled:
            return Response({'error': '2FA is not enabled for this user.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Invalidate any old tokens for 2FA login
        AuthToken.objects.filter(user=user, token_type='2fa_login', is_used=False).update(expires_at=timezone.now())

        # Generate and send a new OTP
        otp = generate_otp()
        AuthToken.objects.create(user=user, otp_code=otp, token_type='2fa_login')
        send_otp_email(user, otp)

        return Response(
            {'message': 'A new 2FA OTP has been sent to your email.'},
            status=status.HTTP_200_OK
        )

# View for user logout
class UserLogoutAPIView(APIView):
    """
    API view to handle user logout by blacklisting the refresh token.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print(request.data)
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({'error': 'Refresh token not provided.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Logout successful.'}, status=status.HTTP_200_OK)
        except Exception as e:
            # A more specific error could be raised by the JWT library if the token is invalid
            return Response({'error': 'Invalid token or token already blacklisted.'}, status=status.HTTP_400_BAD_REQUEST)

# View for user profile
class UserProfileAPIView(APIView):
    """
    API view to get the user's profile details.
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)

# View to update a user's profile
class UpdateProfileAPIView(APIView):
    """
    API view to update a user's profile information.
    """
    permission_classes = [IsAuthenticated]
    def put(self, request):
        serializer = UpdateProfileSerializer(request.user.profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# View to upload a profile picture
class ProfilePictureUploadAPIView(APIView):
    """
    API view to upload a new profile picture.
    """
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = ProfilePictureSerializer(request.user.profile, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Profile picture updated successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# View for changing a user's password
class ChangePasswordAPIView(APIView):
    """
    API view to change the user's password.
    """
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                user = request.user
                user.set_password(serializer.validated_data['new_password'])
                user.save()

                # Log the password change
                PasswordHistory.objects.create(
                    user=user,
                    hashed_password=user.password
                )
                # Log the activity
                UserActivityLog.objects.create(
                    user=user,
                    activity_type='PASSWORD_CHANGE',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                return Response(
                    {'message': 'Password changed successfully.'},
                    status=status.HTTP_200_OK
                )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(f"Error in ChangePasswordAPIView: {e}")
            return Response(
                {'error': 'An internal server error occurred during password change.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PasswordResetRequestAPIView(APIView):
    """
    API view to request a password reset email.
    """
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = User.objects.get(email=serializer.validated_data['email'])
                
                # Invalidate any old tokens for password reset
                AuthToken.objects.filter(user=user, token_type='password_reset', is_used=False).update(expires_at=timezone.now())

                # Create a new token
                token = AuthToken.objects.create(user=user, token_type='password_reset')
                
                # Send the email with the reset link
                subject = 'Password Reset Request'
                message = f'Hi {user.username},\n\nPlease use the following token to reset your password: {token.token}\n\nThis token is valid for 15 minutes.'
                send_email(subject, message, [user.email])

                return Response(
                    {'message': 'Password reset token sent to email.'},
                    status=status.HTTP_200_OK
                )

            except User.DoesNotExist:
                return Response(
                    {'error': 'User with this email not found.'},
                    status=status.HTTP_404_NOT_FOUND
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmAPIView(APIView):
    """
    API view to confirm password reset with a token.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = PasswordResetConfirmSerializer(data=request.data)
            if serializer.is_valid():
                token_uuid = serializer.validated_data['token']
                new_password = serializer.validated_data['new_password']

                # Fetch the token and validate it
                try:
                    token = AuthToken.objects.get(
                        token=token_uuid,
                        token_type='password_reset',
                        is_used=False,
                        expires_at__gt=timezone.now()
                    )
                except AuthToken.DoesNotExist:
                    return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

                user = token.user

                # Maintain only last 10 password histories
                histories = PasswordHistory.objects.filter(user=user).order_by('-created_at')
                if histories.count() >= 10:
                    # Get the oldest password history (by created_at ascending)
                    oldest_password_history = PasswordHistory.objects.filter(user=user).order_by('created_at').first()
                    if oldest_password_history:
                        oldest_password_history.delete()

                # Check for password reuse
                for history in PasswordHistory.objects.filter(user=user):
                    if check_password(new_password, history.hashed_password):
                        return Response({'error': 'Cannot reuse recent passwords.'}, status=status.HTTP_400_BAD_REQUEST)

                # Set and save new password
                user.set_password(new_password)
                user.save()

                # Save new password to history
                PasswordHistory.objects.create(
                    user=user,
                    hashed_password=user.password
                )

                # Mark token as used
                token.is_used = True
                token.save()

                return Response({'message': 'Password reset successfully.'}, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print(f"Error in PasswordResetConfirmAPIView: {e}")
            return Response(
                {'error': 'An internal server error occurred during password reset confirmation.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class Toggle2FAAPIView(APIView):
    """
    API view to enable/disable 2FA for a user.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        profile, created = UserProfile.objects.get_or_create(user=user)
        
        profile.is_2fa_enabled = not profile.is_2fa_enabled
        profile.save()

        if profile.is_2fa_enabled:
            return Response({'message': 'Two-factor authentication enabled successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Two-factor authentication disabled successfully.'}, status=status.HTTP_200_OK)


class DeactivateAccountAPIView(APIView):
    """
    API view to deactivate a user's account.
    """
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        if not user.is_active:
            return Response({'message': 'Account is already deactivated.'}, status=status.HTTP_400_BAD_REQUEST)

        user.is_active = False
        user.save()

        # Invalidate all of the user's refresh tokens to log them out
        for token in OutstandingToken.objects.filter(user=user):
            BlacklistedToken.objects.get_or_create(token=token)

        UserActivityLog.objects.create(
            user=user,
            activity_type='DEACTIVATE_ACCOUNT',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        return Response({'message': 'Account deactivated successfully.'}, status=status.HTTP_200_OK)


class DeleteAccountAPIView(APIView):
    """
    API view to delete a user's account.
    """
    permission_classes = [IsAuthenticated]
    
    def delete(self, request):
        """
        Delete the authenticated user's account.
        """
        user = request.user
        
        # Blacklist all JWT tokens for this user before deletion
        for token in OutstandingToken.objects.filter(user=user):
            BlacklistedToken.objects.get_or_create(token=token)
        
        # Delete the user (cascading deletes will handle related objects)
        user.delete()
        
        return Response(
            {'message': 'Account deleted successfully.'}, 
            status=status.HTTP_204_NO_CONTENT
        )


class EmailChangeRequestAPIView(APIView):
    """
    API view to request an email change.
    """
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = EmailChangeRequestSerializer(data=request.data)
        if serializer.is_valid():
            new_email = serializer.validated_data['new_email']
            user = request.user
            
            if user.email == new_email:
                return Response(
                    {'error': 'New email cannot be the same as the current email.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if the new email is already in use
            if User.objects.filter(email=new_email).exists():
                return Response(
                    {'error': 'This email is already in use.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Invalidate any old email change tokens
            AuthToken.objects.filter(user=user, token_type='email_change', is_used=False).update(expires_at=timezone.now())
            
            # Create a new token
            token = AuthToken.objects.create(
                user=user,
                token_type='email_change',
                new_email=new_email
            )
            
            # Send the email confirmation link to the new address
            subject = 'Confirm your new email address'
            message = f'Hi {user.username},\n\nPlease click the link to confirm your new email address: http://127.0.0.1:8001/auth/email-change-confirm/?token={token.token}'
            send_email(subject, message, [new_email])

            return Response(
                {'message': 'Confirmation email sent to new address.'},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailChangeConfirmAPIView(APIView):
    """
    API view to confirm the email change.
    """
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = EmailChangeConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token_uuid = serializer.validated_data['token']
            try:
                token = AuthToken.objects.get(
                    token=token_uuid,
                    token_type='email_change',
                    is_used=False,
                    expires_at__gt=timezone.now()
                )

                user = token.user
                user.email = token.new_email
                user.save()
                
                token.is_used = True
                token.save()

                return Response(
                    {'message': 'Email updated successfully'},
                    status=status.HTTP_200_OK
                )
            except AuthToken.DoesNotExist:
                return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserActivityLogAPIView(APIView):
    """
    API view to get a user's activity log.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        logs = UserActivityLog.objects.filter(user=request.user).order_by('-timestamp')
        serializer = UserActivityLogSerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UserActivityLogDeleteAPIView(APIView):
    """
    API view to delete a user's activity log.
    """
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        UserActivityLog.objects.filter(user=request.user).delete()
        return Response({'message': 'Activity log deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)

