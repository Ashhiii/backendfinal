from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from users.models import User  # your custom User model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site  # <-- missing import


class RegisterView(APIView):
    def post(self, request):
        data = request.data
        required_fields = ['first_name', 'last_name', 'email', 'password', 'username']

        for field in required_fields:
            if not data.get(field):
                return Response({"message": f"{field} is required!"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=data['email']).exists():
            return Response({"message": "Email is already registered!"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=data['username']).exists():
            return Response({"message": "Username is already taken!"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.create(
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=data['email'],
                username=data['username']
            )
            user.set_password(data['password'])
            user.is_active = False  # deactivate until email verified
            user.save()

            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            current_site = get_current_site(request)
            verification_link = f"http://{current_site.domain}/verify-email/{uid}/{token}/"

            send_mail(
                subject='Verify your email',
                message=f'Hi {user.first_name}, please verify your email by clicking the link: {verification_link}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )

            token_obj, _ = Token.objects.get_or_create(user=user)

            return Response({
                "message": "User created successfully! Please verify your email before login.",
                "token": token_obj.key,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"message": "Invalid link."}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            user.is_verified = True
            user.is_active = True
            user.save()
            return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        data = request.data
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return Response({"message": "Email and password are required!"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "Invalid email or password!"}, status=status.HTTP_401_UNAUTHORIZED)

        user = authenticate(username=user.username, password=password)
        if user is None:
            return Response({"message": "Invalid email or password!"}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
            return Response({"message": "Account inactive. Please verify your email."}, status=status.HTTP_403_FORBIDDEN)

        token, _ = Token.objects.get_or_create(user=user)

        return Response({
            "message": "Login successful!",
            "token": token.key,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            }
        }, status=status.HTTP_200_OK)
