# from django.contrib import admin
# from .models import UserProfile

# @admin.register(UserProfile)
# class UserProfileAdmin(admin.ModelAdmin):
#     list_display = ['user', 'date_of_birth', 'age', 'gender', 'phone_number', 'id']

#     search_fields = ['user__username', 'phone_number', 'id']

#     list_filter = ['gender']


from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin
from .models import UserProfile

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'date_of_birth', 'age', 'gender', 'phone_number', 'id']
    search_fields = ['user__username', 'phone_number', 'id']
    list_filter = ['gender']

# Customize the UserAdmin to include the 'id' field
class CustomUserAdmin(UserAdmin):
    list_display = ('id', 'username', 'email', 'first_name', 'last_name', 'is_staff')

# Unregister the default UserAdmin and register the customized one
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)