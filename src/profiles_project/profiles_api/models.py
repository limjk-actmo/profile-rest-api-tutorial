# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.models import BaseUserManager

from django.conf import settings
from django.utils.translation import gettext_lazy as _

from django.utils.http import int_to_base36
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator as token_generator
from datetime import datetime


class UserProfileManager(BaseUserManager):
    """Helps Django work with our custom user model."""

    def create_user(self, email, name, password=None):
        """Creates a new user profile object."""

        if not email:
            raise ValueError('Users must have an email address.')

        email = self.normalize_email(email)
        user = self.model(email=email, name=name)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, name, password):
        """Creates and saves a new superuser with given details."""

        user = self.create_user(email, name, password)
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)

        return user

    def __str__(self):
        return self.email

class UserProfile(AbstractBaseUser, PermissionsMixin):
    """Represents a "user profile" inside our system."""

    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserProfileManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['name']

    def get_full_name(self):
        """Used to get a users full name."""

        return self.name

    def get_short_name(self):
        """Used to get a users short name."""

        return self.name

    def __str__(self):
        """Django uses this when it needs to convert the object to a string"""

        return self.email


class ProfileFeedItem(models.Model):
    """Profile status update."""
    user_profile = models.ForeignKey("UserProfile", on_delete=models.CASCADE)
    status_text = models.CharField(max_length=255)
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """Return the model as a string."""

        return self.status_text


class PasswordResetManager(models.Manager):
    """ Password Reset Manager """

    def create_for_user(self, user):
        """ create password reset for specified user """
        # support passing email address too
        user = UserProfile.objects.get(email=user)

        token_generator.key_salt = datetime.hour
        temp_key = token_generator.make_token(user)

        # save it to the password reset model
        password_reset = PasswordReset(user=user, temp_key=temp_key)
        password_reset.save()

        domain = settings.DEFAULT_SITE_HOST

        # send the password reset email
        subject = _("Password reset email sent")
        message = render_to_string("email_messages/password_reset_key_message.txt", {
            "user": user,
            "uid": int_to_base36(user.id),
            "temp_key": temp_key,
            "domain": domain,
        })

        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

        return password_reset


class PasswordReset(models.Model):
    """
    Password reset Key
    """
    user = models.ForeignKey("UserProfile", on_delete=models.CASCADE)

    temp_key = models.CharField("temp_key", max_length=100)
    timestamp = models.DateTimeField("timestamp", auto_now_add=True)
    reset = models.BooleanField("reset yet?", default=False)

    objects = PasswordResetManager()

    def __str__(self):
        return "%s (key=%s, reset=%r)" % (
            self.user.name,
            self.temp_key,
            self.reset
        )
