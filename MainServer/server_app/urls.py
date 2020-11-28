from django.contrib import admin
from django.urls import path, re_path
from django.conf.urls import url, include
import server_app.views

admin.autodiscover()

urlpatterns = [
    path('new/', server_app.views.CreateUserView.as_view(), name='new'),
    path('users/', server_app.views.AllUsersView.as_view(), name='all users'),
    path('<username>/info/', server_app.views.UserInfoView.as_view(), name='info'),
    path('<username>/update/', server_app.views.UserUpdateView.as_view(), name='update user'),
    path('<username>/chats/', server_app.views.AllChatsView.as_view(), name='chat list'),
    path('<username>/create-chat-with/<chum>/', server_app.views.CreateChatView.as_view(), name='chat creation'),
    path('<username>/all-messages-with/<chum>/', server_app.views.AllMessagesView.as_view(), name='all messages'),
    path('<username>/add-message-with/<chum>/', server_app.views.AddMessageView.as_view(), name='add message'),
]
