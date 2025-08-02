from django.urls import path
from .views import (
    UserSignupAPIView, 
    UserLoginAPIView, 
    UserLogoutAPIView, 
    UserProfileAPIView, 
    UpdateProfileAPIView, 
    ChangePasswordAPIView, 
    PasswordResetRequestAPIView, 
    PasswordResetConfirmAPIView,
    VerifySignupOTPView,
    Verify2FAOTPView,
    ResendSignupOTPView,
    Resend2FAOTPView,
    Toggle2FAAPIView,
)


urlpatterns = [
    path('signup/', UserSignupAPIView.as_view(), name='signup'),
    path('signup/verify-otp/', VerifySignupOTPView.as_view(), name='verify-signup-otp'),
    path('signup/resend-otp/', ResendSignupOTPView.as_view(), name='resend-signup-otp'),
    path('login/', UserLoginAPIView.as_view(), name='login'),
    path('login/verify-2fa/', Verify2FAOTPView.as_view(), name='verify-2fa-otp'),
    path('login/resend-2fa/', Resend2FAOTPView.as_view(), name='resend-2fa-otp'),
    path('logout/', UserLogoutAPIView.as_view(), name='logout'),
    path('profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('profile/update/', UpdateProfileAPIView.as_view(), name='update-profile'),
    path('password/change/', ChangePasswordAPIView.as_view(), name='password-change'),
    path('password/reset/', PasswordResetRequestAPIView.as_view(), name='password-reset-request'),
    path('password/reset/confirm/', PasswordResetConfirmAPIView.as_view(), name='password-reset-confirm'),
    path('2fa/toggle/', Toggle2FAAPIView.as_view(), name='toggle-2fa'),
]
