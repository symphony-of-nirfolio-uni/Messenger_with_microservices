from django.shortcuts import render
import requests

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from django.utils.timezone import localtime, now


class Login(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        return render(request, template_name='users/login.html',context={'login_result': True})

    def post(self, request):
        username = request.POST.get('username', None)
        password = request.POST.get('password', None)
        token_type = request.POST.get('token_type', None)
        if username == '' or username is None or password is None or password == '' or token_type != 'user':
            return render(request, template_name='users/login.html', context={'login_result': False})
        return Response(request.POST)
