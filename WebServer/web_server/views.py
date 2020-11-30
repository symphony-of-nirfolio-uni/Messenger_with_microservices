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


class Login(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        if 'Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES:
            if verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
                if request.COOKIES['UserType'] == 'admin':
                    return redirect('/profile/admin/' + request.COOKIES['Username'])
                else:
                    return redirect('/profile/user/' + request.COOKIES['Username'])

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
                    return redirect('/profile/user/' + request.COOKIES['Username'])

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

        data = {
            'username': username,
            'email': email,
        }
        token_response = requests.post('http://' + main_server_ip + '/new/',
                                       data=data)

        return render(request, template_name='login.html', context={'sign_up_result': False})
