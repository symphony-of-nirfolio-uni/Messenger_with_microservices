from django.contrib import admin
from django.urls import path
import admin_server.views

admin.autodiscover()

urlpatterns = [
    path('<username>/ban/', admin_server.views.BanView.as_view(), name='chat creation'),
    path('<username>/timeout/', admin_server.views.TimeoutView.as_view(), name='all messages'),
    path('<username>/is-banned/', admin_server.views.IsBannedView.as_view(), name='update user'),
    path('<username>/is-timeout/', admin_server.views.IsTimeoutView.as_view(), name='chat list'),
]
