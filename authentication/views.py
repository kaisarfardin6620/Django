# authentication/views.py
import random
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model, authenticate, login, logout
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail

from .models import UserProfile, OTP
from .serializers import (
    UserSignupSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserProfileNestedSerializer,
    PasswordChangeSerializer,
    PasswordResetSerializer,
    OTPVerificationSerializer
)

User = get_user_model()

def send_otp_email(user, purpose):
    otp_code = str(random.randint(100000, 999999))
    OTP.objects.filter(user=user, purpose=purpose, is_used=False).update(is_used=True)
    OTP.objects.create(user=user, code=otp_code, purpose=purpose)
    
    subject = f'Your {purpose} verification code'
    message = f'Your one-time password for {purpose} is: {otp_code}. It is valid for 5 minutes.'
    send_mail(subject, message, '18192103277@cse.bubt.edu.bd', [user.email], fail_silently=False)

class UserSignupAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            send_otp_email(user, 'signup')
            return Response({'message': 'User registered. Please check your email for OTP to activate your account.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
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
                    return Response({'message': 'Account activated successfully. You can now log in.'}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    
    

class ResendSignupOTPView(APIView):
    """
    Resends an OTP for signup verification.
    """
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
            if user.is_active:
                return Response({'message': 'Account is already active. Please log in.'}, status=status.HTTP_400_BAD_REQUEST)
            send_otp_email(user, 'signup')
            return Response({'message': 'New OTP sent to your email.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)    

class UserLoginAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            
            user = authenticate(request, username=username, password=password)
            
            if user and user.is_active:
                send_otp_email(user, '2fa')
                return Response({'message': 'Authentication successful. Please check your email for the 2FA code to complete your login.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid credentials or inactive account'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class Verify2FAOTPView(APIView):
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']
            
            try:
                user = User.objects.get(email=email)
                otp_entry = OTP.objects.filter(user=user, purpose='2fa').last()

                if otp_entry and otp_entry.is_valid() and otp_entry.code == otp_code:
                    login(request, user)
                    otp_entry.is_used = True
                    otp_entry.save()
                    return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    
    

class Resend2FAOTPView(APIView):
    """
    Resends an OTP for 2FA login.
    """
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
            send_otp_email(user, '2fa')
            return Response({'message': 'New OTP sent to your email.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class UserLogoutAPIView(APIView):
    def get(self, request, *args, **kwargs):
        logout(request)
        return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)

class UserProfileAPIView(APIView):
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'error': 'You must be logged in to view your profile'}, status=status.HTTP_401_UNAUTHORIZED)
        
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UpdateProfileAPIView(APIView):
    def put(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'error': 'You must be logged in to update your profile'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            profile = request.user.userprofile
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserProfileNestedSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordAPIView(APIView):
    def put(self, request, *args, **kwargs):
        user = request.user
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            new_password = serializer.validated_data.get('new_password')
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            return Response({'message': 'Password reset link sent to your email.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class PasswordResetConfirmAPIView(APIView):
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if not all([username, new_password, confirm_password]):
            return Response({'error': 'All fields are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if new_password != confirm_password:
            return Response({'error': 'New passwords must match'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=username)
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
