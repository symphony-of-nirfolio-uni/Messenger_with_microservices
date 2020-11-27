from django.db import models

# Create your models here.


class Users(models.Model):
    user_name = models.CharField(max_length=60, unique=True)
    email = models.CharField(max_length=256, unique=True)
    password_hash = models.CharField(max_length=10000)

    def __str__(self):
        return self.user_name

    class Meta:
        db_table = "users"


class Admins(models.Model):
    admin_name = models.CharField(max_length=60, unique=True)
    email = models.CharField(max_length=256, unique=True)
    password_hash = models.CharField(max_length=10000)
    approved = models.BooleanField(default=False)

    class Meta:
        db_table = "admin_users"
