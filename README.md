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

After running the app once, your folder will look like this:
IVY_Animal_Shelter_App/
   - app.py
   - data/
       - pets.json
       - users.json
       - exports/
           - pets_export.json
   - website_upload/
       - pets.json
   - app_run.bat

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
