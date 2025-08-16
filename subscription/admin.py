from django.contrib import admin
from .models import Customer, Product, Price, Subscription

# Registering models with the default admin interface
admin.site.register(Customer)
admin.site.register(Product)
admin.site.register(Price)
admin.site.register(Subscription)

# You can also create custom admin classes for a better user experience.
# This example provides a more detailed view and filtering options for each model.

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ('user', 'stripe_customer_id', 'created_at')
    search_fields = ('user__username', 'stripe_customer_id')
    list_filter = ('created_at',)
    readonly_fields = ('created_at', 'updated_at')

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'stripe_product_id', 'is_active', 'created_at')
    search_fields = ('name', 'stripe_product_id')
    list_filter = ('is_active', 'created_at')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(Price)
class PriceAdmin(admin.ModelAdmin):
    list_display = ('product', 'stripe_price_id', 'unit_amount', 'currency', 'interval', 'is_active')
    search_fields = ('product__name', 'stripe_price_id')
    list_filter = ('is_active', 'currency', 'interval')
    readonly_fields = ('created_at', 'updated_at')
    list_select_related = ('product',) # Improves performance for foreign key lookups

@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ('customer', 'price', 'stripe_subscription_id', 'status', 'current_period_end', 'cancel_at_period_end')
    search_fields = ('customer__user__username', 'stripe_subscription_id')
    list_filter = ('status', 'cancel_at_period_end')
    readonly_fields = ('created_at', 'updated_at', 'current_period_start', 'current_period_end')
    list_select_related = ('customer', 'price') # Improves performance for foreign key lookups

