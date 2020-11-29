from django.shortcuts import render
import requests

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from server_app.models import UserInfo, ChatList, Message
from django.utils.timezone import localtime, now

wrong_input = {
    'my_error': 'invalid input'
}

login_server_ip = '172.18.0.3:8200'


def user_info_dict(user_info):
    data = {
        'first_name': user_info.first_name,
        'last_name': user_info.last_name,
        'username': user_info.username,
        'email': user_info.email,
        'status': user_info.status,
    }
    return data


def all_user_dict(users):
    usernames = []
    for user in users:
        usernames.append(user.username)
    return {'usernames': usernames}


def verify(token, username, usertype):
    data = {
        'username': username,
        'token': token,
        'user_type': usertype
    }

    response = requests.post('http://' + login_server_ip + '/verify_token/',
                             data=data)
    try:
        return 'verified' in response.json() and response.json()['verified']
    except:
        return False


class UserInfoView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, username):
        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'})

        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            qs = UserInfo.objects.filter(username=username)
            if len(qs) > 0:
                return Response(user_info_dict(qs[0]))
            else:
                return Response({'error': 'user doesn\'t exist'})
        else:
            return Response({'error': 'token not valid'}, status=401)


class CreateUserView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        email = request.POST.get('email', None)
        username = request.POST.get('username', None)
        last_name = request.POST.get('last_name', '')
        first_name = request.POST.get('first_name', '')
        status = request.POST.get('status', '')

        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'})

        if email is None or username is None:
            return Response({'error': 'wrong input data'})
        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            if request.headers['Username'] != username:
                return Response({'error': 'wrong input'}, 400)

            qs = UserInfo.objects.filter(username=username)
            if len(qs) > 0:
                return Response({'error': 'user with such username exists'}, 406)

            qs = UserInfo.objects.filter(email=email)
            if len(qs) > 0:
                return Response({'error': 'user with such email exists'}, 406)

            new_user = UserInfo(
                email=email,
                first_name=first_name,
                last_name=last_name,
                username=username,
                status=status
            )

            new_user.save()
            return Response(status=201)

        else:
            return Response({'error': 'token not valid'}, status=401)


class UserUpdateView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, username):
        last_name = request.POST.get('last_name', '')
        first_name = request.POST.get('first_name', '')
        status = request.POST.get('status', '')

        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'}, 400)

        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            if request.headers['Username'] != username:
                return Response({'error': 'not allowed'}, 405)

            qs = UserInfo.objects.filter(username=username)
            if len(qs) == 0:
                return Response({'error': 'no such user'}, 406)

            update_user = UserInfo.objects.get(username=username)
            update_user.last_name = last_name
            update_user.first_name = first_name
            update_user.status = status
            update_user.save()
            return Response(status=200)

        else:
            return Response({'error': 'token not valid'}, status=401)


class AllUsersView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'})

        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            qs = UserInfo.objects.all()
            return Response(all_user_dict(qs))
        else:
            return Response({'error': 'token not valid'}, status=401)


class CreateChatView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, username, chum):

        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'})

        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            if request.headers['Username'] != username:
                return Response({'error': 'wrong input'}, 400)

            qs1 = UserInfo.objects.filter(username=username)
            if len(qs1) == 0:
                return Response({'error': 'user with such username doesn\'t exist'}, 406)

            qs2 = UserInfo.objects.filter(username=chum)
            if len(qs2) == 0:
                return Response({'error': 'chum with such username doesn\'t exist'}, 406)

            chat1 = ChatList.objects.filter(first_user=qs1[0],
                                            second_user=qs2[0])
            chat2 = ChatList.objects.filter(first_user=qs2[0],
                                            second_user=qs1[0])
            if len(chat1) > 0 or len(chat2) > 0:
                return Response({'error': 'chat exists'}, 406)
            else:
                new_chat = ChatList(first_user=qs1[0],
                                    second_user=qs2[0])
                new_chat.save()
                return Response(status=201)

        else:
            return Response({'error': 'token not valid'}, status=401)


class AllChatsView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, username):
        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'})

        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            if username != request.headers['Username']:
                return Response({'error': 'not allowed'}, status=405)

            user = UserInfo.objects.filter(username=username)

            if len(user) == 0:
                return Response({'error': 'user not exists'}, status=406)

            user = user[0]
            qs1 = ChatList.objects.filter(first_user=user)
            qs2 = ChatList.objects.filter(second_user=user)
            chums = []
            for chum in qs1:
                chums.append(chum.second_user.username)

            for chum in qs2:
                chums.append(chum.first_user.username)
            return Response({'chums': chums})
        else:
            return Response({'error': 'token not valid'}, status=401)


class AddMessageView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, username, chum):

        message = request.POST.get('message')

        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'}, 400)
        if message is None or message == '' or message.isspace():
            return Response({'error': 'wrong input data'}, 400)

        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            if request.headers['Username'] != username:
                return Response({'error': 'wrong input'}, 400)

            user = UserInfo.objects.filter(username=username)
            if len(user) == 0:
                return Response({'error': 'user with such username doesn\'t exist'}, 406)
            user = user[0]
            chum = UserInfo.objects.filter(username=chum)
            if len(chum) == 0:
                return Response({'error': 'chum with such username doesn\'t exist'}, 406)
            chum = chum[0]
            chat1 = ChatList.objects.filter(first_user=user,
                                            second_user=chum)
            chat2 = ChatList.objects.filter(first_user=chum,
                                            second_user=user)

            if len(chat1) == 0 and len(chat2) == 0:
                return Response({'error': 'chat doesn\'t exist'}, 406)
            else:
                chat = chat1[0] if len(chat2) == 0 else chat2[0]

                new_message = Message(
                    chat=chat,
                    message=message,
                    time=localtime(now()),
                    owner=user,
                )
                new_message.save()
                return Response(status=201)

        else:
            return Response({'error': 'token not valid'}, status=401)


class AllMessagesView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, username, chum):
        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'})

        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            if request.headers['Username'] != username:
                return Response({'error': 'wrong input'}, 400)

            user = UserInfo.objects.filter(username=username)
            if len(user) == 0:
                return Response({'error': 'user with such username doesn\'t exist'}, 406)
            user = user[0]
            chum = UserInfo.objects.filter(username=chum)
            if len(chum) == 0:
                return Response({'error': 'chum with such username doesn\'t exist'}, 406)
            chum = chum[0]
            chat1 = ChatList.objects.filter(first_user=user,
                                            second_user=chum)
            chat2 = ChatList.objects.filter(first_user=chum,
                                            second_user=user)
            if len(chat1) == 0 and len(chat2) == 0:
                return Response({'error': 'chat doesn\'t exist'}, 406)

            chat = chat1[0] if len(chat2) == 0 else chat2[0]

            qs = Message.objects.filter(chat=chat).order_by("time")

            messages = []
            for message in qs:
                messages.append(
                    {
                        "id": message.message_id,
                        "owner": message.owner.username,
                        "time": message.time,
                        "message": message.message,
                        "chat_id": message.chat.chat_id,
                    }
                )

            return Response({'messages': messages})
        else:
            return Response({'error': 'token not valid'}, status=401)