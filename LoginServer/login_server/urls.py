from django.contrib import admin
from django.urls import path
import login_server.views

admin.autodiscover()

urlpatterns = [
    path('get_token/', login_server.views.GetTokenView.as_view(), name='get token'),
    path('create_user/', login_server.views.CreateUserView.as_view(), name='create user'),
    path('refresh_token/', login_server.views.RefreshTokenView.as_view(), name='refresh token'),
]
