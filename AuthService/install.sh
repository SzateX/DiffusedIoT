python3 -m pip install -r requirements.txt
python3 generate_secret.py
python3 manage.py migrate
python3 manage.py createsuperuser