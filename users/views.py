from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
reset_tokens = {}

class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"message": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            token = get_random_string(length=32)
            reset_tokens[email] = token  # In real apps, store in DB with expiration

            # Simulate email sending (replace with actual send_mail)
            send_mail(
                'Password Reset',
                f'Your reset token is: {token}',
                'noreply@yourapp.com',
                [email],
                fail_silently=False,
            )

            return Response({"message": "Password reset token sent to email."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"message": "User with that email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        
class ResetPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        token = request.data.get('token')
        new_password = request.data.get('new_password')

        if reset_tokens.get(email) != token:
            return Response({"message": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            del reset_tokens[email]
            return Response({"message": "Password reset successful."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"message": "User not found."}, status=status.HTTP_404_NOT_FOUND)


class RegisterView(APIView):
    def post(self, request):
        data = request.data
        print("Received data:", data)

        required_fields = ['first_name', 'last_name', 'email', 'password', 'username']
        for field in required_fields:
            if not data.get(field):
                return Response({"message": f"{field} is required!"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            if User.objects.filter(email=data['email']).exists():
                return Response({"message": "Email is already registered!"}, status=status.HTTP_400_BAD_REQUEST)

            if User.objects.filter(username=data['username']).exists():
                return Response({"message": "Username is already taken!"}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.create(
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=data['email'],
                username=data['username']
            )
            user.set_password(data['password'])
            user.save()

            token, _ = Token.objects.get_or_create(user=user)

            return Response({
                "message": "User created successfully!",
                "token": token.key,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                }
            }, status=status.HTTP_201_CREATED)

        except ValidationError as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


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

