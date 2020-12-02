from django.shortcuts import render
import requests

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from django.shortcuts import redirect
from login_server.models import Admins, Users
import hashlib
import jwt
import pyDes
import base64
import json
import random
from django.utils.timezone import localtime, now
from datetime import timedelta, datetime
from credentials import SECRET_JWT_KEY

from credentials import ADMIN_CLIENT, SERVER_CLIENT

wrong_input = {
    'error': 'invalid input'
}

keycloak_ip = '172.18.0.4:8080'


def create_access_token(response, data, qs):
    access_token = response['access_token']
    refresh_token = response['refresh_token']
    if data['client_id'] == "ServerClient":
        username = qs.username
    else:
        username = qs.admin_name

    s = str(localtime(now()))
    encode_data = {
        "time": s,
        "duration_access": 1000,
        "duration_refresh": 2000,
        "access_token": access_token,
        "username": username,
        "refresh_token": refresh_token,
    }

    token = jwt.encode(encode_data, SECRET_JWT_KEY, algorithm='HS256')

    ans = {
        "token": token,
    }

    return ans


def verify_token(data, user_type):
    response = requests.get('http://' + keycloak_ip + '/auth/realms/messenger/')
    public_key = response.json()['public_key']
    public_key = '-----BEGIN PUBLIC KEY-----\n' + public_key + '\n-----END PUBLIC KEY-----'

    try:
        access_token_json = jwt.decode(data['access_token'], public_key, algorithms='RS256',
                                       audience=[user_type, 'account'])
        return access_token_json['clientId'] == user_type
    except:
        return False


class GetTokenView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        username = request.POST.get('username', None)
        passwd = request.POST.get('password', None)
        token_type = request.POST.get('token_type', None)
        if passwd is None or username is None or (token_type != 'admin' and token_type != 'user'):
            return Response(wrong_input, status=400)

        if token_type == 'user':
            data = {
                "client_id": "ServerClient",
                "client_secret": SERVER_CLIENT,
                "grant_type": "client_credentials"
            }
        elif token_type == 'admin':
            data = {
                "client_id": "AdminClient",
                "client_secret": ADMIN_CLIENT,
                "grant_type": "client_credentials"
            }
        else:
            data = {}

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post('http://' + keycloak_ip + '/auth/realms/messenger/protocol/openid-connect/token',
                                 data=data, headers=headers)
        if 'access_token' in response.json() and 'refresh_token' in response.json():
            if data['client_id'] == "ServerClient":
                qs = Users.objects.filter(username=username)
                if len(qs) != 0:
                    return Response(create_access_token(response.json(), data, qs[0]), status=201)
            elif data['client_id'] == "AdminClient":
                qs = Admins.objects.filter(admin_name=username)
                if len(qs) != 0:
                    if qs[0].approved is False:
                        return Response({'error': 'admin isn\'t approved'}, status=403)
                    return Response(create_access_token(response.json(), data, qs[0]), status=201)

            return Response({'error': 'user doesn\'t exist'})

        return Response(status=500)


class CreateUserView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        username = request.POST.get('username', None)
        email = request.POST.get('email', None)
        passwd = request.POST.get('password', None)
        repeat_passwd = request.POST.get('repeat_password', None)
        token_type = request.POST.get('token_type', None)
        if username is None or email is None or passwd is None or repeat_passwd is None or token_type is None\
                or (token_type != 'user' and token_type != 'admin'):
            return Response(wrong_input, status=400)

        if passwd != repeat_passwd:
            return Response({'error': 'repeat password is not equal'}, status=406)

        if token_type == 'user':
            qs = Users.objects.filter(username=username)
            if len(qs) > 0:
                return Response({'error': 'username is already occupied'}, status=406)
            qs = Users.objects.filter(email=email)
            if len(qs) > 0:
                return Response({'error': 'email is already used'}, status=406)

            hash_gen = hashlib.sha512()
            hash_gen.update((passwd+username).encode('utf-8'))
            pass_hash = hash_gen.hexdigest()

            new_user = Users(username=username,
                             email=email,
                             password_hash=pass_hash)
            new_user.save()
            return Response({
                'username': username,
                'email': email,
                'password_hash': pass_hash
            })

        else:
            qs = Admins.objects.filter(admin_name=username)
            if len(qs) > 0:
                return Response({'error': 'username is already occupied'}, status=406)
            qs = Admins.objects.filter(email=email)
            if len(qs) > 0:
                return Response({'error': 'email is already used'}, status=406)

            hash_gen = hashlib.sha512()
            hash_gen.update((passwd+username).encode('utf-8'))
            pass_hash = hash_gen.hexdigest()

            new_user = Admins(admin_name=username,
                              email=email,
                              password_hash=pass_hash,
                              approved=False)
            new_user.save()

        return Response(status=201,)


class RefreshTokenView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        token = request.POST.get('token', None)
        username = request.POST.get('username', None)
        user_type = request.POST.get('user_type', None)
        if username is None or token is None or (user_type != 'user' and user_type != 'admin'):
            return Response(wrong_input, status=400)

        if user_type == 'user':
            user_type = 'ServerClient'
            qs = Users.objects.filter(username=username)
            if len(qs) == 0:
                return Response({'error': 'user doesn\'t exist'}, status=406)
            hash_pass = qs[0].password_hash
        else:
            user_type = 'AdminClient'
            qs = Admins.objects.filter(admin_name=username)
            if len(qs) == 0:
                return Response({'error': 'admin doesn\'t exist'}, status=406)
            if qs[0].approved is False:
                return Response({'error': 'admin doesn\'t approved'}, status=406)

            hash_pass = qs[0].password_hash

        data = jwt.decode(token, SECRET_JWT_KEY, algorithm='HS256')

        data['time'] = datetime.strptime(data['time'][:-6], '%Y-%m-%d %H:%M:%S.%f')
        current_time = datetime.strptime(str(localtime(now()))[:-6], '%Y-%m-%d %H:%M:%S.%f')

        if username != data['username'] or (current_time-data['time']) > timedelta(seconds=data['duration_refresh']):
            return Response({'error': 'token not valid'}, status=401)

        if (current_time-data['time']) < timedelta(seconds=data['duration_access']) \
                and verify_token(data, user_type):
            return Response({'verified': True}, status=201)
        else:
            if user_type == "AdminClient":
                data = {
                    "client_id": user_type,
                    "client_secret": ADMIN_CLIENT,
                    "grant_type": "client_credentials"
                }
            else:
                data = {
                    "client_id": user_type,
                    "client_secret": SERVER_CLIENT,
                    "grant_type": "client_credentials"
                }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            response = requests.post('http://' + keycloak_ip + '/auth/realms/messenger/protocol/openid-connect/token',
                                     data=data, headers=headers)

            # return Response(data)
            if 'access_token' in response.json() and 'refresh_token' in response.json():
                return Response(create_access_token(response.json(), data, qs[0]), status=201)

            return Response({'error': 'unknown issue'}, status=500)



