from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# The Customer model links a Django user to a Stripe Customer ID.
# This is crucial for managing subscriptions and payments for a specific user.
class Customer(models.Model):
    """
    Model representing a Stripe Customer.
    Links a Django user to their Stripe customer ID.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='stripe_customer')
    stripe_customer_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.username

# Models to mirror Stripe's Products and Prices
# This is a good practice to manage your pricing plans directly in your app.
class Product(models.Model):
    """
    Model representing a Stripe Product.
    """
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    stripe_product_id = models.CharField(max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class Price(models.Model):
    """
    Model representing a Stripe Price (plan).
    """
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='prices')
    stripe_price_id = models.CharField(max_length=255, unique=True)
    currency = models.CharField(max_length=3)  # e.g., 'usd'
    unit_amount = models.DecimalField(max_digits=10, decimal_places=2)
    interval = models.CharField(max_length=50, choices=[('month', 'Monthly'), ('year', 'Yearly')], default='month')
    is_recurring = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.product.name} - {self.unit_amount} {self.currency}/{self.interval}"

# The Subscription model tracks a user's current subscription status.
# This model will be updated by a webhook to reflect changes from Stripe.
class Subscription(models.Model):
    """
    Model representing a user's subscription to a Stripe plan.
    """
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('trialing', 'Trialing'),
        ('past_due', 'Past Due'),
        ('canceled', 'Canceled'),
        ('unpaid', 'Unpaid'),
        ('incomplete', 'Incomplete'),
        ('incomplete_expired', 'Incomplete Expired'),
    )

    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='subscriptions')
    price = models.ForeignKey(Price, on_delete=models.SET_NULL, null=True, blank=True)
    stripe_subscription_id = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='incomplete')
    current_period_start = models.DateTimeField(null=True, blank=True)
    current_period_end = models.DateTimeField(null=True, blank=True)
    cancel_at_period_end = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.customer.user.username} - {self.price.product.name}"
