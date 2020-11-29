from django.db import models


class BannedUsers(models.Model):
    username = models.CharField(max_length=60, unique=True)
    start_time = models.DateTimeField()
    duration = models.IntegerField()

    class Meta:
        db_table = "banned_users"


class TimeoutUsers(models.Model):
    username = models.CharField(max_length=60, unique=True)
    start_time = models.DateTimeField()
    duration = models.IntegerField()

    class Meta:
        db_table = "timeout_users"

