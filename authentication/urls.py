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
    Verify2FAOTPView,
    Resend2FAOTPView,
    Toggle2FAAPIView,
    DeactivateAccountAPIView,
    DeleteAccountAPIView,
    VerifyEmailLinkAPIView, 
    ResendVerificationLinkAPIView, 
    ProfilePictureUploadAPIView, 
    UserActivityLogAPIView, 
    EmailChangeRequestAPIView, 
    EmailChangeConfirmAPIView 
)


urlpatterns = [
    path('signup/', UserSignupAPIView.as_view(), name='signup'),
    # Choose ONE for signup verification:
    # Option 1: Email Link Verification
    path('verify-email/', VerifyEmailLinkAPIView.as_view(), name='verify-email-link'),
    path('resend-verification-link/', ResendVerificationLinkAPIView.as_view(), name='resend-verification-link'),
    # Option 2: OTP Verification (uncomment if you prefer this for signup, and comment out Option 1 paths)
    # path('signup/verify-otp/', VerifySignupOTPView.as_view(), name='verify-signup-otp'),
    # path('signup/resend-otp/', ResendSignupOTPView.as_view(), name='resend-signup-otp'),

    path('login/', UserLoginAPIView.as_view(), name='login'),
    path('login/verify-2fa/', Verify2FAOTPView.as_view(), name='verify-2fa-otp'),
    path('login/resend-2fa/', Resend2FAOTPView.as_view(), name='resend-2fa-otp'),
    path('logout/', UserLogoutAPIView.as_view(), name='logout'),
    path('profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('profile/update/', UpdateProfileAPIView.as_view(), name='update-profile'),
    path('profile/picture/upload/', ProfilePictureUploadAPIView.as_view(), name='profile-picture-upload'), 
    path('profile/activity-log/', UserActivityLogAPIView.as_view(), name='user-activity-log'), 

    path('password/change/', ChangePasswordAPIView.as_view(), name='password-change'),
    path('password/reset/', PasswordResetRequestAPIView.as_view(), name='password-reset-request'),
    path('password/reset/confirm/', PasswordResetConfirmAPIView.as_view(), name='password-reset-confirm'),
    
    path('email/change/request/', EmailChangeRequestAPIView.as_view(), name='email-change-request'), 
    path('email/change/confirm/', EmailChangeConfirmAPIView.as_view(), name='email-change-confirm'), 

    path('account/deactivate/', DeactivateAccountAPIView.as_view(), name='deactivate-account'),
    path('account/delete/', DeleteAccountAPIView.as_view(), name='delete-account'),
    path('2fa/toggle/', Toggle2FAAPIView.as_view(), name='toggle-2fa'),
]
