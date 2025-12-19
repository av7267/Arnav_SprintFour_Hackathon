from django.contrib import admin
from django.urls import path
from django.shortcuts import redirect  # Add this import
from phishing_detector.views import check_email_phishing

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/check-phishing/', check_email_phishing),
    path('', lambda request: redirect('/api/check-phishing/')),  # Redirect root URL to /api/check-phishing/
]