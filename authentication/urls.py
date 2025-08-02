from django.urls import path
from .views import UserSignupAPIView, UserLoginAPIView, UserLogoutAPIView, UserProfileAPIView, UpdateProfileAPIView, ChangePasswordAPIView, PasswordResetRequestAPIView, PasswordResetConfirmAPIView


urlpatterns = [
    path('signup/', UserSignupAPIView.as_view(), name='signup'),
    path('login/', UserLoginAPIView.as_view(), name='login'),
    path('logout/', UserLogoutAPIView.as_view(), name='logout'),
    path('profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('profile/update/', UpdateProfileAPIView.as_view(), name='update-profile'),
    path('password/change/', ChangePasswordAPIView.as_view(), name='password-change'),
    path('password/reset/', PasswordResetRequestAPIView.as_view(), name='password-reset-request'),
    path('password/reset/confirm/', PasswordResetConfirmAPIView.as_view(), name='password-reset-confirm'),
]
