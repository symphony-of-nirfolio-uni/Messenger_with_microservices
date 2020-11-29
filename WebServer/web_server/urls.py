from django.contrib import admin
from django.urls import path, re_path
from django.conf.urls import url, include
import web_server.views

admin.autodiscover()

urlpatterns = [
    path('login/', web_server.views.Login.as_view(), name='new')
]
