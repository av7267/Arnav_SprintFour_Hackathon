from django.urls import path
from . import views

urlpatterns = [
    path('', views.detect_url, name='detect_url'),
    path('scan-inbox/', views.scan_inbox, name='scan_inbox'),
]