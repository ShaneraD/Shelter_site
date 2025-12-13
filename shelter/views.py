from django.shortcuts import render

def home(request):
    return render(request, 'shelter/home.html')

def animals(request):
    return render(request, 'shelter/animals.html')

def login(request):
    return render(request, 'shelter/login.html')

