Biometric MVP (Face++)
----------------------
How to run:
1. Create a virtualenv and install requirements: pip install -r requirements.txt
2. Set your Face++ keys in environment or edit biometric_auth/settings.py:
   - FACEPP_API_KEY
   - FACEPP_API_SECRET
3. Run migrations: python manage.py migrate
4. Create a superuser if you want: python manage.py createsuperuser
5. Run server: python manage.py runserver 0.0.0.0:8000
6. Visit /signup/ to create an account, then /biometrics/enroll/face/ to enroll and /biometrics/verify/ to verify.
