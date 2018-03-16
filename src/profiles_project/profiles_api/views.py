# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib.sessions import exceptions
from django.shortcuts import render
from django.utils.http import base36_to_int

from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework import filters
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics
from rest_framework.renderers import TemplateHTMLRenderer


from . import serializers
from . import models
from . import permissions

# Create your views here.

class HelloApiView(APIView):
    """Test API View."""

    serializer_class = serializers.HelloSerializer

    def get(self, request, format=None):
        """Returns a list of APIView features."""
        an_apiview = [
            'Uses HTTP methods as function (get, post, patch, put, delete)',
            'It is similar to a traditional Django view',
            'Gives you the most control over your logic',
            'Is mapped manually to URLs'
        ]

        return Response({'message': 'Hello!',
                         'an_apiview': an_apiview})

    def post(self, request):
        """Create a hello message with our name."""

        serializer = serializers.HelloSerializer(data=request.data)
        if serializer.is_valid():
            name = serializer.data.get('name')
            message = 'Hello {0}!'.format(name)
            return Response({'message':message})
        else:
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def put(self, request, pk=None):
        """Handles updating an object."""

        return Response({'method': 'put'})


    def patch(self, request, pk=None):
        """Patch request, only updates fields provided in the request."""

        return Response({'method': 'patch'})


    def delete(self, request, pk=None):
        """Deletes and object."""

        return Response({'method': 'delete'})


class HelloViewSet(viewsets.ViewSet):
    """Test API ViewSet."""

    serializer_class = serializers.HelloSerializer

    def list(self, request):
        """Return a hello message."""

        a_viewset = [
            'Uses actions (list, create, retrieve, update, partial_update)',
            'Automatically maps to URLs using Routers',
            'Provides more functionality with less code.'
        ]

        return Response({'message': 'Hello!', 'a_viewset': a_viewset})


    def create(self, request):
        """Create a new hello message."""

        serializer = serializers.HelloSerializer(data=request.data)

        if serializer.is_valid():
            name = serializer.data.get('name')
            message = 'Hello {0}'.format(name)
            return Response({'message': message})
        else:
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST)


    def retrieve(self, request, pk=None):
        """Handles getting an object by its ID."""

        return Response({'http_method': 'GET'})


    def update(self, request, pk=None):
        """Handles updating an object."""

        return Response({'http_method': 'PUT'})


    def partial_update(self, request, pk=None):
        """Handles updating part of an object."""

        return Response({'http_method': 'PATCH'})


    def destroy(self, request, pk=None):
        """Handles removing an object."""

        return Response({'http_method': 'DELETE'})


class UserProfileViewSet(viewsets.ModelViewSet):
    """Handles creating, and updating profiles."""

    serializer_class = serializers.UserProfileSerializer
    queryset = models.UserProfile.objects.all()
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.UpdateOwnProfile,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('name', 'email',)


class LoginViewSet(viewsets.ViewSet):
    """Checks and email and password and returns an auth token."""

    serializer_class = AuthTokenSerializer

    def create(self, request):
        """Use the ObtainAuthToken APIView to validate and creat a token."""

        return ObtainAuthToken().post(request)


class UserProfileFeedViewSet(viewsets.ModelViewSet):
    """Handles creating, reading and updating profile feed items."""

    authentication_classes = (TokenAuthentication,)
    serializer_class = serializers.ProfileFeedItemSerializer
    queryset = models.ProfileFeedItem.objects.all()
    # permission_classes = (permissions.PostOwnStatus, IsAuthenticatedOrReadOnly)
    permission_classes = (permissions.PostOwnStatus, IsAuthenticated)

    def perform_create(self, serializer):
        """Sets the user profile to the logged in user."""

        serializer.save(user_profile=self.request.user)


from .forms import ResetPasswordForm, ResetPasswordKeyForm

class PasswordResetRequestKey(generics.GenericAPIView):
    """
    Sends an email to the user email address with a link to reset his password.

    **TODO:** the key should be sent via push notification too.

    **Accepted parameters:**

     * email
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (permissions.IsNotAuthenticated,)
    serializer_class = serializers.ResetPasswordSerializer

    def post(self, request, format=None):
        # init form with POST data
        serializer = self.serializer_class(data=request.data)
        # validate
        if serializer.is_valid():
            serializer.save()
            return Response({
                'detail': 'We just sent you the link with which you will able to reset your password at %s' % request.data.get('email')
            })
        # in case of errors
        return Response(serializer.errors, status=400)

    def permission_denied(self, request):
        raise exceptions.PermissionDenied("You can't reset your password if you are already authenticated")


account_password_reset = PasswordResetRequestKey.as_view()


class PasswordResetFromKey(generics.GenericAPIView):
    """
    Reset password from key.

    **The key must be part of the URL**!

    **Accepted parameters:**

     * password1
     * password2
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (permissions.IsNotAuthenticated,)
    serializer_class = serializers.ResetPasswordKeySerializer

    def post(self, request, uidb36, key, format=None):
        # pull out user
        try:
            uid_int = base36_to_int(uidb36)
            password_reset_key = models.PasswordReset.objects.get(user_id=uid_int, temp_key=key, reset=False)
        except (ValueError, models.PasswordReset.DoesNotExist, AttributeError):
            return Response({'errors': 'Key Not Found'}, status=404)

        serializer = serializers.ResetPasswordKeySerializer(
            data=request.data,
            instance=password_reset_key
        )

        # validate
        if serializer.is_valid():
            serializer.save()
            return Response({'detail': 'Password successfully changed.'})
        # in case of errors
        return Response(serializer.errors, status=400)

    def permission_denied(self, request):
        raise exceptions.PermissionDenied("You can't reset your password if you are already authenticated")


account_password_reset_key = PasswordResetFromKey.as_view()