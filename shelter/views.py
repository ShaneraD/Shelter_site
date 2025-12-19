from django.shortcuts import render

def employee_login(request):
    return render(request, 'shelter/employee_login.html')

def home(request):
    return render(request, 'shelter/home.html')

def animals(request):
    return render(request, 'shelter/animals.html')

def user_login(request):
    return render(request, 'shelter/login.html')

def employee_dashboard(request):
    return render(request, 'shelter/employee_dashboard.html')

def intake_form(request):
    return render(request, 'shelter/intake_form.html')
