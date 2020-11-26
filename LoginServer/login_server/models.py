from django.db import models

# Create your models here.


class Users(models.Model):
    user_name = models.CharField(max_length=60)
    email = models.CharField(max_length=256)

    def __str__(self):
        return self.user_name