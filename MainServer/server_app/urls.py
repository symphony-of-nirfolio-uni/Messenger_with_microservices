from django.contrib import admin
from django.urls import path, re_path
from django.conf.urls import url, include
import server_app.views

admin.autodiscover()

urlpatterns = [
    path('<int:user_id>/', server_app.views.get_id),
    path('<int:user_id>/info/', server_app.views.user_info),
    path('new', server_app.views.create_user),
    path('hello/', server_app.views.hello),
]
