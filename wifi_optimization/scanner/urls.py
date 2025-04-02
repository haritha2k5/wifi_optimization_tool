from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('',views.dashboard,name='dashboard'),
    path('scan/',views.scan_wifi,name='scan_wifi'),
    path('speed/',views.get_speed_test,name='get_speed_test'),
]