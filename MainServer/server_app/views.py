from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from server_app.models import UserInfo, ChatList, Message


# Create your views here.


def hello(request):
    return render(request, "hello.html", {})


def get_id(request, user_id=None):
    text = "Displaying number: " + str(user_id)
    print(request.headers)
    return HttpResponse(text)


def user_info(request, user_id=None):
    data = {
        'id': user_id,
        'info': 'wow'*(user_id % 4),
    }
    return JsonResponse(data)


def create_user(request):
    email = ''
    first_name = ''
    if request.method == "GET":
        email = request.GET.get('email', None)
        first_name = request.GET.get('first_name', None)

    elif request.method == "POST":
        email = request.POST.get('email', None)
        first_name = request.POST.get('first_name', None)

    return HttpResponse(str(email) + " yep " + str(first_name))

'''
def create_user(request, email, first_name=''):

    
    if UserInfo.objects.get(email=email) is None:
        user_1 = UserInfo(
            email=email,
            first_name=first_name,
            last_name=last_name,
            user_name=user_name,
        )
        user_1.save()
        objects = UserInfo.objects.all()
        res = ""
        for el in objects:
            res += el.email + "<br >"
        return HttpResponse(res)
    else:
        return HttpResponse("REJECTED")
    
    # res = ""
    # for el in request.META:
    #     res += str(el) + " " + str(request.META[el]) + "<br />"
    return HttpResponse(email + " " + first_name)
'''