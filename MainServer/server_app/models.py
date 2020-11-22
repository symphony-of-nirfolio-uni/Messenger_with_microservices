from django.db import models

# Create your models here.


class UserInfo(models.Model):
    user_id = models.IntegerField(unique=True, primary_key=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    user_name = models.CharField(max_length=100, unique=True)
    email = models.CharField(max_length=50, unique=True)
    status = models.CharField(max_length=500)
    profile_pic = models.BinaryField()

    class Meta:
        db_table = "user_info"


class ChatList(models.Model):
    chat_id = models.IntegerField(unique=True, primary_key=True)
    first_user = models.ForeignKey('UserInfo', related_name='first_user', on_delete=models.CASCADE)
    second_user = models.ForeignKey('UserInfo', related_name='second_user', on_delete=models.CASCADE)

    class Meta:
        db_table = "chat_list"


class Message(models.Model):
    message_id = models.IntegerField(unique=True, primary_key=True)
    chat = models.ForeignKey('ChatList', on_delete=models.CASCADE)
    message = models.CharField(max_length=10000)
    time = models.DateTimeField()
    owner = models.ForeignKey('UserInfo', on_delete=models.CASCADE)

    class Meta:
        db_table = "messages"
