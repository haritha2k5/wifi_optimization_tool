from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('',views.dashboard,name='dashboard'),
    path('scan/',views.scan_wifi,name='scan_wifi'),
    path('speed/',views.get_speed_test,name='get_speed_test'),
    path('ping-test/', views.ping_test, name='ping_test'),
    path('network-info/', views.get_network_info, name='network_info'),
    path('best-channel/', views.suggest_best_channel, name='best_channel'),
    path('devices/', views.connected_devices, name='connected_devices'),
]


