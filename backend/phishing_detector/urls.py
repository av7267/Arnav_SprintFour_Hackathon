from django.urls import path
from . import views

urlpatterns = [
    path('', views.register_view, name='register'),   # Root shows registration
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('detect-url/', views.detect_url, name='detect_url'),  # Home page
    path('scan-inbox/', views.scan_inbox, name='scan_inbox'),
]