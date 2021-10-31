import jwt
from rooms.serializers import RoomSerializer
from rest_framework.fields import REGEX_TYPE
from users import serializers
from users.serializers import UserSerializer
from rest_framework.decorators import api_view, authentication_classes, permission_classes, action
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework import status
from django.contrib.auth import authenticate
from django.conf import settings
from . import models
from .permissions import IsSelf
from rooms import models as room_models

# Create your views here.
class UserViewSet(ModelViewSet):

    queryset = models.User.objects.all()
    serializer_class = UserSerializer

    def get_permissions(self):
        permission_classes = []
        if self.action == "list":
            permission_classes = [IsAdminUser]
        elif self.action == "create" or self.action == "retrieve" or self.action == "favs":
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsSelf]

        return [permission() for permission in permission_classes]

    @action(detail=False, methods=["post"])
    def login(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        if not username or not password:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=username, password=password)
        if user is not None:
            encode_jwt = jwt.encode({"pk": user.pk}, settings.SECRET_KEY, algorithm="HS256")
            return Response(data={'token': encode_jwt, 'id': user.pk})
        else:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

    @action(detail=True)
    def favs(self, request, pk):
        user = self.get_object()
        print(user)
        serializer = RoomSerializer(user.favs.all(), many=True).data
        return Response(serializer)

    @favs.mapping.put
    def toggle_favs(self, request, pk):
        pk = request.data.get("pk", None)
        user = request.user
        if pk is not None:
            try:
                room = room_models.Room.objects.get(pk=pk)
                if room in user.favs.all():
                    user.favs.remove(room)
                else:
                    user.favs.add(room)
                return Response()
            except room_models.Room.DoesNotExist:
                pass
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


# class UsersView(APIView):
#     def post(self, request):
#         serializer = UserSerializer(request.data)
#         if serializer.is_valid():
#             new_user = serializer.save()
#             return Response(UserSerializer(new_user))
#         else:
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class MeView(APIView):

#     def get(self, request):
#         if request.user.is_authenticated:
#             return Response(UserSerializer(request.user).data)

#     def put(self, request):
#         serializer = UserSerializer(request.user, data=request.data, partial=True)
#         if serializer.is_valid():
#             serializer.save()
#             return Response()
#         else:
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FavsView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = RoomSerializer(user.favs.all(), many=True).data
        return Response(serializer)

    def put(self, request):
        pk = request.data.get("pk", None)
        user = request.user
        if pk is not None:
            try:
                room = room_models.Room.objects.get(pk=pk)
                if room in user.favs.all():
                    user.favs.remove(room)
                else:
                    user.favs.add(room)
                return Response()
            except room_models.Room.DoesNotExist:
                pass
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


# @api_view(["GET"])
# def user_detail(request, pk):
#     try:
#         user = models.User.objects.get(pk=pk)
#         return Response(UserSerializer(user).data)
#     except models.User.DoesNotExist:
#         return Response(status=status.HTTP_404_NOT_FOUND)

# @api_view(["POST"])
# def login(request):
#     username = request.data.get("username")
#     password = request.data.get("password")
#     if not username or not password:
#         return Response(status=status.HTTP_400_BAD_REQUEST)
#     user = authenticate(username=username, password=password)
#     if user is not None:
#         encode_jwt = jwt.encode({"pk": user.pk}, settings.SECRET_KEY, algorithm="HS256")
#         return Response(data={'token': encode_jwt})
#     else:
#         return Response(status=status.HTTP_401_UNAUTHORIZED)
    