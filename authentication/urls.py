from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView,
)
from .views import (
    UserSignupAPIView,
    VerifySignupOTPView,
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
    EmailChangeConfirmAPIView,
    MyTokenObtainPairView
)

urlpatterns = [
    # JWT authentication paths
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    # User signup and verification (choose one method by commenting out the other)
    path('signup/', UserSignupAPIView.as_view(), name='signup'),
    # Option 1: Email Link Verification
    path('verify-email/', VerifyEmailLinkAPIView.as_view(), name='verify-email'),
    path('verify-email/resend/', ResendVerificationLinkAPIView.as_view(), name='resend-verification'),
    # Option 2: OTP Verification
    #path('signup/verify-otp/', VerifySignupOTPView.as_view(), name='verify-signup-otp'),

    # Login and 2FA
    path('login/', UserLoginAPIView.as_view(), name='login'),
    path('login/verify-2fa/', Verify2FAOTPView.as_view(), name='verify-2fa'),
    path('login/resend-2fa/', Resend2FAOTPView.as_view(), name='resend-2fa'),
    path('logout/', UserLogoutAPIView.as_view(), name='logout'),

    # Profile management
    path('profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('profile/update/', UpdateProfileAPIView.as_view(), name='update-profile'),
    path('profile/picture/upload/', ProfilePictureUploadAPIView.as_view(), name='profile-picture-upload'),
    path('profile/activity-log/', UserActivityLogAPIView.as_view(), name='user-activity-log'),
    path('profile/toggle-2fa/', Toggle2FAAPIView.as_view(), name='toggle-2fa'),
    path('profile/deactivate/', DeactivateAccountAPIView.as_view(), name='deactivate-account'),
    path('profile/delete/', DeleteAccountAPIView.as_view(), name='delete-account'),

    # Password and Email
    path('password/change/', ChangePasswordAPIView.as_view(), name='password-change'),
    path('password/reset/', PasswordResetRequestAPIView.as_view(), name='password-reset-request'),
    path('password/reset/confirm/', PasswordResetConfirmAPIView.as_view(), name='password-reset-confirm'),
    path('email/change/request/', EmailChangeRequestAPIView.as_view(), name='email-change-request'),
    path('email/change/confirm/', EmailChangeConfirmAPIView.as_view(), name='email-change-confirm'),
]