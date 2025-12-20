# IVY Animal Shelter - Inventory Manager

A simple desktop app for an animal shelter to:
- Log in with a username/password
- Add / edit / delete pets
- View inventory in a searchable table
- Export and “Upload” pet listings to a customer-facing website using a JSON file

**Default Admin Login**
- Username: `admin`
- Password: `admin123`

---

## Project Structure

After running the app and website, your folder will look like this:

- app.py  
- run_app.bat  

- data/  
  - pets.json  
  - users.json  
  - exports/  
    - pets_export.json  

- website_upload/  
  - pets.json  

- shelter/  
  - views.py  
  - urls.py  
  - templates/  
    - shelter/  
      - base.html  
      - home.html  
      - animals.html  
      - employee_login.html  
      - employee_dashboard.html  
      - intake_form.html  
  - static/  
    - shelter/  
      - dog.jpg  
      - cat.jpg  
      - style.css  

- shelter_site/  
- manage.py  
- venv/  


## Requirements

- Python 3.10+
- Uses only built-in Python libraries

## How to use the app

- Open app_run.bat 
- Login using the provided admin credentials
- enter pet information
- Select any of the options below to save to .json.
- Upload to website adds the .json file to the website_upload folder.
- The website will look for changes in that folder to update itself.
- This app also features a simple identity management system for end users (staff)

## Website
-Activate virtual enviroment 
- Run python manage.py runserver
- Open browser and go to http://127.0.0.1:8000/
  
  ## Website Behavior
- The desktop app manages all pet data
- The website does not edit pets
- The website reads from website_upload/pets.json
- Dogs and Cats are displayed separately based on species
- Updating pet data requires re-uploading JSON from the desktop app



