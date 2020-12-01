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
            return 1, response.json()['end_time']
        else:
            return 0, None
    except:
        return -1, None


class Login(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        if 'Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES:
            if verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
                if request.COOKIES['UserType'] == 'admin':
                    return redirect('/profile/admin/')
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
            response = redirect('/profile/admin/')

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
                    return redirect('/profile/admin/')
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

        new_token = request.COOKIES['Token']
        if not verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
            new_token = refresh(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType'])
            if 'ans_token' not in new_token:
                return redirect('/login/')
            new_token = new_token['ans_token']

        header = {
            'Username': request.COOKIES['Username'],
            'Token': request.COOKIES['Token'],
            'UserType': request.COOKIES['UserType']
        }

        banned, end_time = is_banned(header)
        if banned == 1:
            return render(request, template_name='banned.html', context={'end_time': end_time})
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

            response = render(request, template_name='profile_user.html', context=context)
            response.set_cookie('Token', new_token)
            return response
        except:
            return render(request, template_name='error.html', context={'error': token_response.content})


class AdminProfileView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        if not ('Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES) or\
                request.COOKIES['UserType'] == 'user':
            return redirect('/login/')

        new_token = request.COOKIES['Token']
        if not verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
            new_token = refresh(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType'])
            if 'ans_token' not in new_token:
                return redirect('/login/')
            new_token = new_token['ans_token']

        header = {
            'Username': request.COOKIES['Username'],
            'Token': new_token,
            'UserType': request.COOKIES['UserType']
        }

        try:
            token_response = requests.get('http://' + main_server_ip + '/users/',
                                          headers=header)
            users = token_response.json()['usernames']

            context = {
                'you_are': header['Username'],
                'users': users
            }

            response = render(request, template_name='profile_admin.html', context=context)

            response.set_cookie('Token', new_token)
            return response
        except:
            return render(request, template_name='error.html', context={'error': token_response.content})


class BanUserView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, username):
        if not ('Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES) or\
                request.COOKIES['UserType'] == 'user':
            return redirect('/login/')

        new_token = request.COOKIES['Token']
        if not verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
            new_token = refresh(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType'])
            if 'ans_token' not in new_token:
                return redirect('/login/')
            new_token = new_token['ans_token']

        header = {
            'Username': request.COOKIES['Username'],
            'Token': new_token,
            'UserType': request.COOKIES['UserType']
        }

        try:
            token_response = requests.get('http://' + admin_server_ip + '/' + username + '/is-banned/',
                                          headers=header)
            banned = token_response.json()['is_banned']
            if banned != "false":
                banned = token_response.json()['end_time']
            else:
                banned = None

            context = {
                'username': username,
                'banned': banned,
            }

            response = render(request, template_name='ban_user.html', context=context)
            response.set_cookie('Token', new_token)
            return response
        except:
            return render(request, template_name='error.html', context={'error': token_response.content})

    def post(self, request, username):
        if not ('Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES) or \
                request.COOKIES['UserType'] == 'user':
            return redirect('/login/')

        new_token = request.COOKIES['Token']
        if not verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
            new_token = refresh(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType'])
            if 'ans_token' not in new_token:
                return redirect('/login/')
            new_token = new_token['ans_token']

        header = {
            'Username': request.COOKIES['Username'],
            'Token': new_token,
            'UserType': request.COOKIES['UserType']
        }
        duration = request.POST.get('duration')
        try:
            data = {'duration': duration}
            token_response = requests.post('http://' + admin_server_ip + '/' + username + '/ban/',
                                           headers=header,
                                           data=data)

            if token_response.status_code != 200:
                return render(request, template_name='error.html', context={'error': token_response.content})
            response = redirect('/ban/' + username)
            response.set_cookie('Token', new_token)
            return response
        except:
            return render(request, template_name='error.html', context={'error': token_response.content})


class TimeoutUserView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, username):
        if not ('Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES) or\
                request.COOKIES['UserType'] == 'user':
            return redirect('/login/')

        new_token = request.COOKIES['Token']
        if not verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
            new_token = refresh(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType'])
            if 'ans_token' not in new_token:
                return redirect('/login/')
            new_token = new_token['ans_token']

        header = {
            'Username': request.COOKIES['Username'],
            'Token': new_token,
            'UserType': request.COOKIES['UserType']
        }

        try:
            token_response = requests.get('http://' + admin_server_ip + '/' + username + '/is-timeout/',
                                          headers=header)
            timeout = token_response.json()['is_timeout']
            if timeout != "false":
                timeout = token_response.json()['end_time']
            else:
                timeout = None

            context = {
                'username': username,
                'timeout': timeout,
            }

            response = render(request, template_name='timeout_user.html', context=context)
            response.set_cookie('Token', new_token)
            return response
        except:
            return render(request, template_name='error.html', context={'error': token_response.content})

    def post(self, request, username):
        if not ('Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES) or \
                request.COOKIES['UserType'] == 'user':
            return redirect('/login/')

        new_token = request.COOKIES['Token']
        if not verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
            new_token = refresh(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType'])
            if 'ans_token' not in new_token:
                return redirect('/login/')
            new_token = new_token['ans_token']

        header = {
            'Username': request.COOKIES['Username'],
            'Token': new_token,
            'UserType': request.COOKIES['UserType']
        }
        duration = request.POST.get('duration')
        try:
            data = {'duration': duration}
            token_response = requests.post('http://' + admin_server_ip + '/' + username + '/timeout/',
                                           headers=header,
                                           data=data)

            if token_response.status_code != 200:
                return render(request, template_name='error.html', context={'error': token_response.content})
            response = redirect('/timeout/' + username)
            response.set_cookie('Token', new_token)
            return response
        except:
            return render(request, template_name='error.html', context={'error': token_response.content})


class ChatView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request, username, chum):
        if not ('Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES) or \
                request.COOKIES['UserType'] == 'admin':
            return redirect('/login/')

        new_token = request.COOKIES['Token']
        if not verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
            new_token = refresh(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType'])
            if 'ans_token' not in new_token:
                return redirect('/login/')
            new_token = new_token['ans_token']

        header = {
            'Username': request.COOKIES['Username'],
            'Token': new_token,
            'UserType': request.COOKIES['UserType']
        }
        if username != header['Username']:
            response = redirect('profile/user/' + header['Username'] + '/')
            response.set_cookie('Token', new_token)
            return response
        try:
            token_response = requests.get('http://' + main_server_ip + '/' + username +
                                          '/all-messages-with/' + chum + '/',
                                          headers=header)
            chat = token_response.json()['messages']
            chat_list = []
            for mes in chat:
                chat_list.append([mes['owner'], mes['message'], mes['time']])

            context = {
                'username': username,
                'chum': chum,
                'chat': chat_list,
            }

            response = render(request, template_name='chat.html', context=context)
            response.set_cookie('Token', new_token)
            return response
        except:
            return render(request, template_name='error.html', context={'error': token_response.content})

    def post(self, request, username, chum):
        if not ('Username' in request.COOKIES and 'Token' in request.COOKIES and 'UserType' in request.COOKIES) or \
                request.COOKIES['UserType'] == 'admin':
            return redirect('/login/')

        new_token = request.COOKIES['Token']
        if not verify(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType']):
            new_token = refresh(request.COOKIES['Username'], request.COOKIES['Token'], request.COOKIES['UserType'])
            if 'ans_token' not in new_token:
                return redirect('/login/')
            new_token = new_token['ans_token']

        header = {
            'Username': request.COOKIES['Username'],
            'Token': new_token,
            'UserType': request.COOKIES['UserType']
        }
        if username != header['Username']:
            response = redirect('profile/user/' + header['Username'] + '/')
            response.set_cookie('Token', new_token)
            return response
        try:
            data = {'message': request.POST.get('message')}
            token_response = requests.post('http://' + main_server_ip + '/' + username +
                                           '/add-message-with/' + chum + '/',
                                           headers=header,
                                           data=data)

            #if token_response.status_code != 200:
            #   return render(request, template_name='error.html', context={'error': token_response.content})

            response = redirect('/' + username + '/chat-with/' + chum + '/')
            response.set_cookie('Token', new_token)
            return response
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