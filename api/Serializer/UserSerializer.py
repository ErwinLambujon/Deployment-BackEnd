from rest_framework import serializers
from api.Model.CustomUser import CustomUser
from django.contrib.auth import authenticate
from django.core.cache import cache
import logging
import time
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ["id", "first_name", "last_name", "email", "password", "user_type"]
        read_only_fields = ["is_active", "is_staff", "date_joined"]
        extra_kwargs = {
            'user_type': {'error_messages': {'invalid_choice': 'Please select either Student or Teacher.'}}
        }

    def validate(self, data):
        start_time = time.time()
        try:
            # Validate password
            validate_password(data.get('password'))

            # Validate user_type
            user_type = data.get('user_type')
            if user_type not in [CustomUser.STUDENT, CustomUser.TEACHER]:
                raise serializers.ValidationError({
                    'user_type': 'Invalid user type. Must be either STUDENT or TEACHER.'
                })

        except ValidationError as e:
            raise serializers.ValidationError({'password': list(e.messages)})

        logger.info(f"Data validation took: {time.time() - start_time} seconds")
        return data

    def validate_email(self, value):
        cache_key = f"email_exists_{value}"
        email_exists = cache.get(cache_key)

        if email_exists is None:
            email_exists = CustomUser.objects.filter(email=value).exists()
            cache.set(cache_key, email_exists, timeout=300)  # Cache for 5 minutes

        if email_exists:
            raise serializers.ValidationError("Email already exists.")
        return value

    def create(self, validated_data):
        user = CustomUser(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            user_type=validated_data['user_type']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class LoginUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['email', 'password']


