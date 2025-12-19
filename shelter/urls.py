from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('animals/', views.animals, name='animals'),
    path('login/', views.user_login, name='login'),
    path('employe/login/',views.employee_login, name='employee_login'),
    path('employee/dashboard/', views.employee_dashboard, name='employee_dashboard'),
    ]
