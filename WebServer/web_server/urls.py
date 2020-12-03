from django.contrib import admin
from django.urls import path, re_path
from django.conf.urls import url, include
import web_server.views

admin.autodiscover()

urlpatterns = [
    path('login/', web_server.views.Login.as_view(), name='login'),
    path('logout/', web_server.views.Logout.as_view(), name='logout'),
    path('sign_up/', web_server.views.SignUpView.as_view(), name='sign up'),
    path('user_list/', web_server.views.UserListView.as_view(), name='user list'),
    path('profile/user/<username>/', web_server.views.UserProfileView.as_view(), name='user profile view'),
    path('profile/update/<username>/', web_server.views.UpdateProfileView.as_view(), name='user profile view'),
    path('profile/admin/users/', web_server.views.AdminProfileView.as_view(), name='admin page users'),
    path('profile/admin/not_approved/', web_server.views.NotApprovedAdminsView.as_view(), name='not approved admins'),
    path('profile/admin/approve/<admin_name>/', web_server.views.ApproveAdminView.as_view(), name='approve admin'),
    path('ban/<username>/', web_server.views.BanUserView.as_view(), name='ban user'),
    path('timeout/<username>/', web_server.views.TimeoutUserView.as_view(), name='ban user'),
    path('<username>/chat-with/<chum>/', web_server.views.ChatView.as_view(), name='chat'),
]
