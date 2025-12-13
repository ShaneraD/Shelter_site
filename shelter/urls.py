from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('animals/', views.animals, name='animals'),
    path('login/', views.login, name='login'),
]
