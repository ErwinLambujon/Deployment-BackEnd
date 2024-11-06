from django.contrib.auth import authenticate, login
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import NotFound
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import viewsets, mixins, status
from rest_framework.response import Response
from rest_framework.decorators import action
from django.db import transaction
import time
import logging
from rest_framework.throttling import AnonRateThrottle
from ..Model.CustomUser import CustomUser
from ..Serializer.UserSerializer import UserSerializer, LoginUserSerializer

logger = logging.getLogger(__name__)

class UserRegistrationThrottle(AnonRateThrottle):
    rate = '5/minute'  # Limit to 5 registration attempts per minute
class UserView(mixins.ListModelMixin,
               mixins.CreateModelMixin,
               mixins.RetrieveModelMixin,
               viewsets.GenericViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def get_serializer_class(self):
        if self.action == 'login':
            return LoginUserSerializer
        if self.action == 'register':
            return UserSerializer
        return self.serializer_class

    def get_object(self):
        pk = self.kwargs.get('pk')
        email = self.kwargs.get('email')

        print(email)

        if pk is not None:
            try:
                return self.queryset.get(pk=pk)
            except CustomUser.DoesNotExist:
                raise NotFound('User with this primary key doesnt\' exists.')

        if email is not None:
            try:
                return self.queryset.get(email=email)
            except CustomUser.DoesNotExist:
                raise NotFound("User with this email doesn't exist.")

        raise NotFound("User not found")

    @action(detail=False, methods=['post'])
    def login(self, request):
        print(request.data)
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "Email and password are required."})

        user = authenticate(email=email, password=password)
        print(user)

        if user is None:
            print(f"Authentication failed for user: {email}")
            return Response({"error": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

        token, created = Token.objects.get_or_create(user=user)
        return Response({"token": token.key})

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def logout(self, request):
        if request.user is None:
            return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            token = Token.objects.get(user=request.user)
            token.delete()

            return Response({"message": "Logout successful."}, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response({"error": "No token found for the user."}, status=status.HTTP_400_BAD_REQUEST)


    @action(detail=False, methods=['post'])
    @action(detail=False, methods=['post'])
    def register(self, request):
        start_time = time.time()
        logger.info("Starting user registration")

        try:
            with transaction.atomic():
                serializer = self.get_serializer(data=request.data)

                serializer_init_time = time.time()
                logger.info(f"Serializer initialization took: {serializer_init_time - start_time} seconds")

                if serializer.is_valid():
                    validation_time = time.time()
                    logger.info(f"Validation took: {validation_time - serializer_init_time} seconds")

                    user = serializer.save()
                    save_time = time.time()
                    logger.info(f"Save took: {save_time - validation_time} seconds")

                    # Create authentication token
                    token = Token.objects.create(user=user)
                    token_time = time.time()
                    logger.info(f"Token creation took: {token_time - save_time} seconds")

                    total_time = time.time() - start_time
                    if total_time > 10:  # Log warning if total time exceeds 10 seconds
                        logger.warning(f"Slow registration detected: {total_time} seconds")

                    return Response({
                        "message": "User registered successfully.",
                        "token": token.key,
                        "user_type": user.user_type,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name
                    }, status=status.HTTP_201_CREATED)

                logger.error(f"Registration validation error: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.exception("Registration failed")
            return Response(
                {"error": "Registration failed. Please try again."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


    @action(detail=False, methods=['get'])
    def get_currently_login(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)