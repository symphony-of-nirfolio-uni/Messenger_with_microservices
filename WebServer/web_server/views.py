from django.shortcuts import render, redirect
import requests

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from django.utils.timezone import localtime, now


main_server_ip = '172.18.0.2:8100'
login_server_ip = '172.18.0.3:8200'
admin_server_ip = '172.18.0.5:8400'


def verify(username, token, usertype):
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


def refresh(username, token, usertype):
    data = {
        'username': username,
        'token': token,
        'user_type': usertype
    }

    response = requests.post('http://' + login_server_ip + '/refresh_token/',
                             data=data)
    try:
        return response.json()
    except:
        return {'error': 'unknown error'}


def is_banned(header):
    response = requests.get('http://' + admin_server_ip + '/' + header['Username'] + '/is-banned/',
                            headers=header)
    try:
        if response.json()['is_banned'] == "true":
            return 1
        else:
            return 0
    except:
        return -1


class Login(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        if 'Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES:
            if verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
                if request.COOKIES['UserType'] == 'admin':
                    return redirect('/profile/admin/' + request.COOKIES['Username'])
                else:
                    return redirect('/profile/user/' + request.COOKIES['Username'] + '/')

        return render(request, template_name='login.html', context={'login_result': True})

    def post(self, request):
        username = request.POST.get('username', None)
        password = request.POST.get('password', None)
        token_type = request.POST.get('token_type', None)
        if username == '' or username is None or password is None or password == '' or \
                (token_type != 'admin' and token_type != 'user'):
            return render(request, template_name='login.html', context={'login_result': False})

        data = {
            'username': username,
            'password': password,
            'token_type': token_type,
        }

        token_response = requests.post('http://' + login_server_ip + '/get_token/',
                                       data=data)

        try:
            if 'ans_token' not in token_response.json():
                return render(request, template_name='login.html', context={'login_result': False})
        except:
            return render(request, template_name='login.html', context={'login_result': False})

        if token_type == 'user':
            response = redirect('/profile/user/' + username)
        else:
            response = redirect('/profile/admin/' + username)

        response.set_cookie('Token', token_response.json()['ans_token'])
        response.set_cookie('Username', username)
        response.set_cookie('UserType', token_type)

        return response


class SignUpView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        if 'Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES:
            if verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
                if request.COOKIES['UserType'] == 'admin':
                    return redirect('/profile/admin/' + request.COOKIES['Username'])
                else:
                    return redirect('/profile/user/' + request.COOKIES['Username'] + '/' + '/')

        return render(request, template_name='sign_up.html')

    def post(self, request):
        username = request.POST.get('username', None)
        email = request.POST.get('email', None)
        password = request.POST.get('password', None)
        repeat_password = request.POST.get('repeat_password', None)
        token_type = request.POST.get('token_type', None)

        if username == '' or username is None or password is None or password == '' or email is None or email == '' or\
                (token_type != 'admin' and token_type != 'user'):
            return render(request, template_name='sign_up.html', context={'sign_up_result': False})

        if password != repeat_password:
            return render(request, template_name='sign_up.html', context={'password_result': False})

        data = {
            'username': username,
            'email': email,
            'password': password,
            'repeat_password': repeat_password,
            'token_type': token_type,
        }

        token_response = requests.post('http://' + login_server_ip + '/create_user/',
                                       data=data)
        if token_response.status_code != 201:
            try:
                if token_response.json()['error'] == 'username is already occupied':
                    return render(request, template_name='sign_up.html', context={'username_result': False})
                elif token_response.json()['error'] == 'email is already used':
                    return render(request, template_name='sign_up.html', context={'email_result': False})
            except:
                return render(request, template_name='sign_up.html', context={'sign_up_result': False})
            return render(request, template_name='sign_up.html', context={'sign_up_result': False})

        if token_type == 'user':
            data = {
                'username': username,
                'token_type': token_type,
                'password': password
            }
            token_response = requests.post('http://' + login_server_ip + '/get_token/',
                                           data=data)

            header = {
                'Token': token_response.json()['ans_token'],
                'Username': username,
                'UserType': token_type
            }
        else:
            header = {}

        data = {
            'username': username,
            'email': email,
        }

        token_response = requests.post('http://' + main_server_ip + '/new/',
                                       data=data,
                                       headers=header)

        return render(request, template_name='login.html', context={'sign_up_result': False})


class UserProfileView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, username):
        if not ('Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES) or\
                request.COOKIES['UserType'] == 'admin':
            return redirect('/login/')

        if not verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
            new_token = refresh(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType'])
            if 'ans_token' not in new_token:
                return redirect('/login/')

        header = {
            'Username': request.COOKIES['Username'],
            'Token': request.COOKIES['Token'],
            'UserType': request.COOKIES['UserType']
        }

        banned = is_banned(header)
        if banned == 1:
            return render(request, template_name='banned.html')
        elif banned == -1:
            return render(request, template_name='error.html', context={'error': 'admin service is closed'})

        try:
            token_response = requests.get('http://' + main_server_ip + '/' + username + '/info/',
                                          headers=header)
            context = {
                'username': token_response.json()['username'],
                'email': token_response.json()['email'],
                'first_name': token_response.json()['first_name'],
                'last_name': token_response.json()['last_name'],
                'status': token_response.json()['status'],
                'you_are': header['Username']
            }
            token_response = requests.get('http://' + main_server_ip + '/' + context['you_are'] + '/chats/',
                                          headers=header)
            if context['you_are'] == context['username']:
                context['chums'] = token_response.json()['chums']
            else:
                chums = token_response.json()['chums']
                for chum in chums:
                    if chum == context['username']:
                        context['can_talk'] = True
                if 'can_talk' not in context:
                    context['can_talk'] = False
            return render(request, template_name='profile_user.html', context=context)
        except:
            return render(request, template_name='error.html', context={'error': token_response.content})


class Logout(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        response = redirect('/login/')
        if 'Username' in request.COOKIES:
            response.delete_cookie('Username')
        if 'Token' in request.COOKIES:
            response.delete_cookie('Token')
        if 'UserType' in request.COOKIES:
            response.delete_cookie('UserType')

        return response