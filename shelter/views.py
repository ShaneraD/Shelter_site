from django.shortcuts import render
import json
from pathlib import Path

def load_pets_from_json():
    json_path = Path("website_upload/pets.json")
    if not json_path.exists():
        return []
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("pets", [])


def employee_login(request):
    return render(request, 'shelter/employee_login.html')

def home(request):
    pets = load_pets_from_json()
    return render(request, 'shelter/home.html', {'pets': pets})

def animals(request):
    pets = load_pets_from_json()
    species_filter = request.GET.get("species")

    if species_filter:
        pets = [
            pet for pet in pets
            if pet.get("species") == species_filter
        ]

    return render(request, 'shelter/animals.html', {'pets': pets})

def user_login(request):
    return render(request, 'shelter/login.html')

def employee_dashboard(request):
    return render(request, 'shelter/employee_dashboard.html')

def intake_form(request):
    return render(request, 'shelter/intake_form.html')
