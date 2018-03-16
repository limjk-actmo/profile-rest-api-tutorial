from rest_framework import serializers
from . import models


class HelloSerializer(serializers.Serializer):
    """Serializes a name field for testing our APIView"""

    name = serializers.CharField(max_length=10)


class UserProfileSerializer(serializers.ModelSerializer):
    """A serializer for our user profile objects."""

    class Meta:
        model = models.UserProfile
        fields = ('id', 'email', 'name', 'password')
        extra_kwargs = {
            'password':
            {
                'write_only': True
            }
        }

    def create(self, validated_data):
        """Create and return a new user."""

        user = models.UserProfile(
            email=validated_data['email'],
            name=validated_data['name']
        )

        user.set_password(validated_data['password'])
        user.save()

        return user

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            if attr == 'password':
                instance.set_password(value)
            else:
                setattr(instance, attr, value)

        instance.save()
        return instance


class ProfileFeedItemSerializer(serializers.ModelSerializer):
    """A serializer for profile feed items."""

    class Meta:
        model = models.ProfileFeedItem
        fields = ('id', 'user_profile', 'status_text', 'created_on')
        extra_kwargs = {
            'user_profile':
            {
                'read_only': True
            }
        }


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, attrs):
        """ ensure email is in the database """

        try:
            condition = models.UserProfile.objects.get(email__iexact=attrs, is_active=True)
        except:
            raise serializers.ValidationError("Email address not verified for any user account")

        return attrs

    def create(self, attrs, instance=None):
        """ create password reset for user """
        password_reset = models.PasswordReset.objects.create_for_user(attrs["email"])

        return password_reset


class ResetPasswordKeySerializer(serializers.Serializer):
    password1 = serializers.CharField(
        help_text='New Password',
    )
    password2 = serializers.CharField(
        help_text='New Password (confirmation)',
    )

    def validate(self, attrs):
        """
        password2 check
        """
        password_confirmation = attrs['password1']
        password = attrs['password2']

        if password_confirmation != password:
            raise serializers.ValidationError('Password confirmation mismatch')

        return attrs

    def update(self, instance, attrs):
        """ change password """
        user = instance.user
        user.set_password(attrs["password1"])
        user.save()
        # mark password reset object as reset
        instance.reset = True
        instance.save()

        return instance