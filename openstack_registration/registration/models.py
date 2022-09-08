from __future__ import unicode_literals

from django.db import models


# Create your models here.
class UserActivation(models.Model):
    link = models.TextField(null=False)
    username = models.CharField(max_length=32, null=False)
    expiration_date = models.DateField(auto_now_add=True, auto_now=False)


class UserInfo(models.Model):
    username = models.CharField(max_length=32, null=False)
    creation_date = models.DateField(auto_now_add=True, auto_now=False)
    last_agreement = models.DateField(auto_now_add=False, auto_now=False)
    enabled = models.BooleanField(default=False)
    admin = models.BooleanField(default=False)
    countForce = models.IntegerField(default=0)
    # group = models.CharField(max_length=32, null=False, default='')

    def __unicode__(self):
        return self.username


class GroupInfo(models.Model):
    group_name = models.CharField(max_length=32, null=False)
    administrators = models.ManyToManyField(UserInfo, through='IsAdmin')

    def __unicode__(self):
        return self.group_name


class IsAdmin(models.Model):
    administrators = models.ForeignKey(UserInfo, on_delete=models.CASCADE)
    group = models.ForeignKey(GroupInfo, on_delete=models.CASCADE)
