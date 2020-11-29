from django.shortcuts import render

# Create your views here.
import requests

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from admin_server.models import BannedUsers, TimeoutUsers
from django.utils.timezone import localtime, now
from datetime import timedelta

login_server_ip = '172.18.0.3:8200'
main_server_ip = '172.18.0.2:8100'


def user_exists(username, admin_name, token, usertype):

    header = {
        'Username': admin_name,
        'Token': token,
        'UserType': usertype
    }
    response = requests.get('http://' + main_server_ip + '/' + username + '/info/',
                            headers=header)
    try:
        return 'username' in response.json() and response.json()['username'] == username
    except:
        return False


def verify(token, username, usertype):
    data = {
        'username': username,
        'token': token,
        'user_type': usertype
    }

    response = requests.post('http://' + login_server_ip + '/verify_token/',
                             data=data)
    try:
        return 'verified' in response.json() and response.json()['verified'] and usertype == 'admin'
    except:
        return False


class BanView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, username):
        duration = request.POST.get('duration')

        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'}, status=400)
        duration = int(duration)
        if duration is None or duration < -1:
            return Response({'error': 'wrong input data'}, status=400)

        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            if user_exists(username, request.headers['Username'], request.headers['Token'], request.headers['UserType']):
                qs = BannedUsers.objects.filter(username=username)
                if len(qs) == 0:
                    banned_user = BannedUsers(
                        username=username,
                        start_time=localtime(now()),
                        duration=duration
                    )
                    banned_user.save()
                else:
                    banned_user = BannedUsers.objects.get(username=username)
                    banned_user.start_time = localtime(now())
                    banned_user.duration = duration
                    banned_user.save()

                return Response(status=200)
            else:
                return Response({'error': 'user doesn\'t exist'}, status=406)
        else:
            return Response({'error': 'token not valid'}, status=401)


class IsBannedView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, username):

        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'}, status=400)

        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            if user_exists(username, request.headers['Username'], request.headers['Token'], request.headers['UserType']):
                qs = BannedUsers.objects.filter(username=username)
                if len(qs) == 0:
                    return Response({'is_banned': 'false'}, status=200)
                else:
                    end_time = qs[0].start_time + timedelta(seconds=qs[0].duration)
                    if end_time < localtime(now()):
                        return Response({'is_banned': 'false'}, status=200)
                    else:
                        return Response({'is_banned': 'true',
                                         'end_time': end_time}, status=200)
            else:
                return Response({'error': 'user doesn\'t exist'}, status=406)
        else:
            return Response({'error': 'token not valid'}, status=401)


class TimeoutView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, username):
        duration = request.POST.get('duration')

        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'}, status=400)
        duration = int(duration)
        if duration is None or duration < -1:
            return Response({'error': 'wrong input data'}, status=400)

        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            if user_exists(username, request.headers['Username'], request.headers['Token'], request.headers['UserType']):
                qs = TimeoutUsers.objects.filter(username=username)
                if len(qs) == 0:
                    timeout_user = TimeoutUsers(
                        username=username,
                        start_time=localtime(now()),
                        duration=duration
                    )
                    timeout_user.save()
                else:
                    timeout_user = TimeoutUsers.objects.get(username=username)
                    timeout_user.start_time = localtime(now())
                    timeout_user.duration = duration
                    timeout_user.save()

                return Response(status=200)
            else:
                return Response({'error': 'user doesn\'t exist'}, status=406)
        else:
            return Response({'error': 'token not valid'}, status=401)


class IsTimeoutView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, username):

        if 'Token' not in request.headers or 'Username' not in request.headers or 'UserType' not in request.headers:
            return Response({'error': 'wrong header data'}, status=400)

        if verify(request.headers['Token'], request.headers['Username'], request.headers['UserType']):
            if user_exists(username, request.headers['Username'], request.headers['Token'], request.headers['UserType']):
                qs = TimeoutUsers.objects.filter(username=username)
                if len(qs) == 0:
                    return Response({'is_timeout': 'false'}, status=200)
                else:
                    end_time = qs[0].start_time + timedelta(seconds=qs[0].duration)
                    if end_time < localtime(now()):
                        return Response({'is_timeout': 'false'}, status=200)
                    else:
                        return Response({'is_timeout': 'true',
                                         'end_time': end_time}, status=200)
            else:
                return Response({'error': 'user doesn\'t exist'}, status=406)
        else:
            return Response({'error': 'token not valid'}, status=401)