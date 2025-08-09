from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView,
)
from .views import (
    MyTokenObtainPairView, UserSignupAPIView, VerifySignupOTPView, VerifyEmailLinkAPIView, ResendVerificationLinkAPIView, LoginView, Verify2FALoginView, Resend2FAOTPView,
    UserLogoutAPIView, UserProfileAPIView, UpdateProfileAPIView, ChangePasswordAPIView, PasswordResetRequestAPIView, PasswordResetConfirmAPIView, Toggle2FAAPIView, DeactivateAccountAPIView,
    DeleteAccountAPIView, ProfilePictureUploadAPIView, UserActivityLogAPIView, EmailChangeRequestAPIView, EmailChangeConfirmAPIView, ResendSignupOTPView,
)

urlpatterns = [
    # JWT authentication paths
    path('token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    # User signup and verification
    path('signup/', UserSignupAPIView.as_view(), name='signup'),
    
    # Verification endpoints
    path('verify-email/', VerifyEmailLinkAPIView.as_view(), name='verify-email'),
    path('verify-email/resend/', ResendVerificationLinkAPIView.as_view(), name='resend-verification'),
    path('verify-signup-otp/', VerifySignupOTPView.as_view(), name='verify-signup-otp'),
    path('verify-signup-otp/resend/', ResendSignupOTPView.as_view(), name='resend-signup-otp'),

    # Login and 2FA
    path('login/', LoginView.as_view(), name='login'),
    path('login/verify-2fa/', Verify2FALoginView.as_view(), name='verify-2fa'),
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
    path('email-change-confirm/', EmailChangeConfirmAPIView.as_view(), name='email-change-confirm-alias'),
]
