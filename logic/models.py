from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    username = models.CharField(max_length=150, unique=True,)
    email = models.EmailField(max_length=150, unique=True)
    password = models.CharField(max_length=255, null=False, blank=False)
    account_type = models.CharField(max_length=20, null=False, blank=False, default='Free')
    terms = models.BooleanField(max_length=255, null=False, blank=False, default='False')


class FA(models.Model):
    user_id = models.CharField(unique=True,)
    code = models.CharField(max_length=6, null=False, blank=False)