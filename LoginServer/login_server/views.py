from django.shortcuts import render
import requests

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from django.shortcuts import redirect

wrong_input = {
    'my_error': 'invalid input'
}

keycloak_ip = '172.18.0.4:8080'


class GetTokenView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        username = request.POST.get('username', None)
        passwd = request.POST.get('password', None)
        token_type = request.POST.get('token_type', None)
        if passwd is None or username is None or (token_type != 'admin' and token_type != 'user'):
            return Response(wrong_input)
        else:
            if token_type == 'admin':
                client_id = "AdminClient"
            elif token_type == 'user':
                client_id = "ServerClient"
            else:
                client_id = ""
            print(client_id)
            data = {
                "username": username,
                "password": passwd,
                "client_id": client_id,
                "client_secret": "",
                "grant_type": "password"
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            response = requests.post('http://' + keycloak_ip + '/auth/realms/messenger/protocol/openid-connect/token',
                                     data=data, headers=headers)

            return Response(response.json())


class CreateUserView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        return redirect('http://localhost:8300/auth/realms/messenger/account')

    # TODO do registration via keycloak api
