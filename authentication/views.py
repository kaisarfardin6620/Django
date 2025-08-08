from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model, authenticate, login, logout
from django.core.mail import send_mail
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
import random
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import UserProfile, OTP, EmailVerificationToken, UserActivityLog, EmailChangeToken, PasswordHistory
from .serializers import (
    UserSignupSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    PasswordChangeSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    OTPVerificationSerializer,
    AccountDeactivateSerializer,
    AccountDeleteSerializer,
    EmailVerificationSerializer,
    ProfilePictureUploadSerializer,
    EmailChangeRequestSerializer,
    EmailChangeConfirmSerializer,
    MyTokenObtainPairSerializer,
    UserActivityLogSerializer
)

User = get_user_model()

def log_user_activity(user, activity_type, request=None, details=None):
    ip_address = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR'))
    if ip_address:
        ip_address = ip_address.split(',')[0].strip()  
    UserActivityLog.objects.create(
        user=user,
        activity_type=activity_type,
        ip_address=ip_address,
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        details=details
    )

class UserSignupAPIView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            log_user_activity(user, activity_type='User Signup', request=request)

            # Option 1: Email Link Verification
            token = EmailVerificationToken.objects.create(user=user)
            verification_url = request.build_absolute_uri(reverse('verify-email'))
            send_mail(
                'Verify your email address',
                f'Please send a POST request to {verification_url} with the following JSON body: {{"token": "{token.token}"}}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            # Option 2: OTP Verification
            # otp = ''.join(random.choices('0123456789', k=6))
            # OTP.objects.create(
            #     user=user,
            #     code=otp,
            #     purpose='signup',
            #     expires_at=timezone.now() + timezone.timedelta(minutes=5)
            # )
            # send_mail(
            #     'Your Signup OTP',
            #     f'Your one-time password for signup verification is: {otp}',
            #     settings.DEFAULT_FROM_EMAIL,
            #     [user.email],
            #     fail_silently=False,
            # )

            return Response({'message': 'User created successfully. Verification email sent.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifySignupOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                otp_obj = OTP.objects.get(code=serializer.validated_data['otp'], purpose='signup', is_used=False)
                if not otp_obj.is_valid():
                    return Response({'message': 'Invalid or expired OTP.'}, status=status.HTTP_400_BAD_REQUEST)
                user = otp_obj.user
                if user.is_active:
                    return Response({'message': 'Account already verified.'}, status=status.HTTP_200_OK)
                user.is_active = True
                user.save()
                otp_obj.is_used = True
                otp_obj.save()
                log_user_activity(user, activity_type='Signup OTP Verified', request=request)
                return Response({'message': 'Account verified successfully.'}, status=status.HTTP_200_OK)
            except OTP.DoesNotExist:
                return Response({'message': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

class UserLoginAPIView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            user_profile = user.userprofile

            if user_profile.is_2fa_enabled:
                otp = ''.join(random.choices('0123456789', k=6))
                OTP.objects.create(
                    user=user,
                    code=otp,
                    purpose='2fa',
                    expires_at=timezone.now() + timezone.timedelta(minutes=5)
                )
                send_mail(
                    'Your 2FA OTP',
                    f'Your one-time password is: {otp}',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                return Response({'message': '2FA enabled. OTP sent to your email.'}, status=status.HTTP_200_OK)
            else:
                login(request, user)
                log_user_activity(user, activity_type='Login Success', request=request)
                refresh = RefreshToken.for_user(user)
                return Response({
                    'message': 'Login successful.',
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({'detail': 'Refresh token not provided.'}, status=status.HTTP_400_BAD_REQUEST)
            token = RefreshToken(refresh_token)
            token.blacklist()
            log_user_activity(request.user, activity_type='Logout', request=request)
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_profile = UserProfile.objects.get(user=request.user)
        serializer = UserProfileSerializer(user_profile)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UpdateProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user_profile = UserProfile.objects.get(user=request.user)
        serializer = UserProfileSerializer(user_profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            log_user_activity(request.user, activity_type='Profile Updated', request=request)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            PasswordHistory.objects.create(user=user, hashed_password=user.password)
            log_user_activity(user, activity_type='Password Changed', request=request)
            return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestAPIView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_url = request.build_absolute_uri(reverse('password-reset-confirm'))
            send_mail(
                'Password Reset Request',
                f'Please send a POST request to {reset_url} with the following JSON body: {{"uidb64": "{uidb64}", "token": "{token}"}}',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            log_user_activity(user, activity_type='Password Reset Requested', request=request)
            return Response({'message': 'Password reset link sent to your email.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            user.set_password(serializer.validated_data['password'])
            user.save()
            PasswordHistory.objects.create(user=user, hashed_password=user.password)
            log_user_activity(user, activity_type='Password Reset Confirmed', request=request)
            return Response({'message': 'Password has been successfully reset.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Verify2FAOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                otp_obj = OTP.objects.get(code=serializer.validated_data['otp'], purpose='2fa', is_used=False)
                if not otp_obj.is_valid():
                    return Response({'message': 'Invalid or expired OTP.'}, status=status.HTTP_400_BAD_REQUEST)
                user = otp_obj.user
                otp_obj.is_used = True
                otp_obj.save()
                login(request, user)
                log_user_activity(user, activity_type='2FA OTP Verified', request=request)
                refresh = RefreshToken.for_user(user)
                return Response({
                    'message': 'OTP verified. Login successful.',
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }, status=status.HTTP_200_OK)
            except OTP.DoesNotExist:
                return Response({'message': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Resend2FAOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if not user.userprofile.is_2fa_enabled:
            return Response({'message': '2FA is not enabled for this user.'}, status=status.HTTP_400_BAD_REQUEST)
        OTP.objects.filter(user=user, purpose='2fa', is_used=False).delete()
        otp = ''.join(random.choices('0123456789', k=6))
        OTP.objects.create(
            user=user,
            code=otp,
            purpose='2fa',
            expires_at=timezone.now() + timezone.timedelta(minutes=5)
        )
        send_mail(
            'Your 2FA OTP',
            f'Your one-time password is: {otp}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        log_user_activity(user, activity_type='2FA OTP Resent', request=request)
        return Response({'message': 'New OTP sent to your email.'}, status=status.HTTP_200_OK)

class Toggle2FAAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_profile = request.user.userprofile
        user_profile.is_2fa_enabled = not user_profile.is_2fa_enabled
        user_profile.save()
        log_user_activity(request.user, activity_type='2FA Toggled', request=request, details=f'2FA has been {"enabled" if user_profile.is_2fa_enabled else "disabled"}.')
        return Response(
            {'message': f'Two-factor authentication has been {"enabled" if user_profile.is_2fa_enabled else "disabled"}.'},
            status=status.HTTP_200_OK
        )

class DeactivateAccountAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = AccountDeactivateSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            user.is_active = False
            user.save()
            logout(request)
            log_user_activity(user, activity_type='Account Deactivated', request=request)
            return Response({'message': 'Account has been deactivated.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DeleteAccountAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = AccountDeleteSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            log_user_activity(user, activity_type='Account Deleted', request=request, details='User account was permanently deleted.')
            user.delete()
            logout(request)
            return Response({'message': 'Account has been permanently deleted.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailLinkAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                token_obj = EmailVerificationToken.objects.get(token=serializer.validated_data['token'])
                user = token_obj.user
                if user.is_active:
                    return Response({'message': 'Email is already verified.'}, status=status.HTTP_200_OK)
                user.is_active = True
                user.save()
                token_obj.delete()
                log_user_activity(user, activity_type='Email Verified', request=request)
                return Response({'message': 'Email has been successfully verified.'}, status=status.HTTP_200_OK)
            except EmailVerificationToken.DoesNotExist:
                return Response({'message': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResendVerificationLinkAPIView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'message': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
            if user.is_active:
                return Response({'message': 'Email is already verified.'}, status=status.HTTP_400_BAD_REQUEST)
            EmailVerificationToken.objects.filter(user=user).delete()
            token = EmailVerificationToken.objects.create(user=user)
            verification_url = request.build_absolute_uri(reverse('verify-email'))
            send_mail(
                'Verify your email address',
                f'Please send a POST request to {verification_url} with the following JSON body: {{"token": "{token.token}"}}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            log_user_activity(user, activity_type='Resend Verification Link', request=request)
            return Response({'message': 'New verification email sent.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'message': 'No user found with this email address.'}, status=status.HTTP_400_BAD_REQUEST)

class ProfilePictureUploadAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_profile = request.user.userprofile
        serializer = ProfilePictureUploadSerializer(user_profile, data=request.data)
        if serializer.is_valid():
            serializer.save()
            log_user_activity(request.user, activity_type='Profile Picture Uploaded', request=request)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserActivityLogAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        logs = UserActivityLog.objects.filter(user=request.user).order_by('-timestamp')
        serializer = UserActivityLogSerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class EmailChangeRequestAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = EmailChangeRequestSerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid():
            new_email = serializer.validated_data['new_email']
            EmailChangeToken.objects.filter(user=request.user).delete()
            token_obj = EmailChangeToken.objects.create(user=request.user, new_email=new_email)
            change_url = request.build_absolute_uri(reverse('email-change-confirm'))
            send_mail(
                'Confirm Email Change',
                f'Please send a POST request to {change_url} with the following JSON body: {{"token": "{token_obj.token}"}}',
                settings.DEFAULT_FROM_EMAIL,
                [new_email],
                fail_silently=False,
            )
            log_user_activity(request.user, activity_type='Email Change Requested', request=request, details=f'Request to change email to {new_email}')
            return Response({'message': 'Email change confirmation link sent to your new email.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmailChangeConfirmAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = EmailChangeConfirmSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            log_user_activity(user, activity_type='Email Change Confirmed', request=request, details=f'Email successfully changed to {user.email}')
            return Response({'message': 'Email has been successfully changed.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)