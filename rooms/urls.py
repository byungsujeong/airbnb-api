# from rest_framework import routers
from rest_framework.routers import DefaultRouter
# from django.urls import path
from . import views
from . import viewsets

app_name = "rooms"
router = DefaultRouter()
router.register("", views.RoomViewSet)

urlpatterns = router.urls

# urlpatterns = [
    # path("", views.RoomsView.as_view()),
    # path("search/", views.room_search),
    # path("<int:pk>/", views.RoomView.as_view()),
# ]
