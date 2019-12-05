import requests
from django import forms

from MQTTHub.settings import AUTH_SERVICE_ADDRESS


class AuthServiceApi(object):
    @staticmethod
    def verify_token(request):
        response = requests.post(
            AUTH_SERVICE_ADDRESS + "/api/user_auth/verify_token/",
            json={
                "token": request.COOKIES.get('user_token'),

            })
        return response.status_code == 200

    @staticmethod
    def get_me(token):
        response = requests.get(
            AUTH_SERVICE_ADDRESS + "/api/get_me/",
            headers={
                'Authorization': "Bearer " + token
            }
        )
        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.text)
        return response.json()

    @staticmethod
    def get_hubs():
        response = requests.get(
            AUTH_SERVICE_ADDRESS + "/api/hubs/")
        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.content)
        return response.json()

    @staticmethod
    def get_hub(hub_id):
        response = requests.get(
            AUTH_SERVICE_ADDRESS + "/api/hub/%d/" % hub_id,
        )
        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.text)
        return response.json()

    @staticmethod
    def get_devices(token, hub):
        response = requests.get(
            hub['private_address'] + "/hub/internal_api/devices_for_user/",
            headers={
                'Authorization': "Bearer " + token
            }
        )
        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.text)
        return response.json()

    @staticmethod
    def sign_in(username, password):
        response = requests.post(
            AUTH_SERVICE_ADDRESS + "/api/user_auth/sign_in/", json={
                "username": username,
                "password": password
            })
        if response.status_code != 200:
            raise forms.ValidationError(response.json().get('detail'))
        return response


class InternalApi(object):
    @staticmethod
    def save_device(token, hub, form):
        response = requests.post(
            hub['private_address'] + "/hub/internal_api/devices_for_user/",
            headers={
                'Authorization': "Bearer " + token
            },
            json={
                'name':  form.cleaned_data['name'],
                'type_of_device':  form.cleaned_data['type_of_device']
            }
        )
        if response.status_code not in [200, 201]:
            raise Exception("Error in connection with InternalApi: "
                            + response.text)

    @staticmethod
    def get_device(token, hub, device_id):
        response = requests.get(
            hub['private_address'] + "/hub/internal_api/devices_for_user/%d/" % int(device_id),
            headers={
                'Authorization': "Bearer " + token
            },
        )
        if response.status_code not in [200]:
            raise Exception("Error in connection with AuthService: "
                            + response.text)
        return response.json()

    @staticmethod
    def update_device(token, hub, device_id, form):
        response = requests.put(
            hub['private_address'] + "/hub/internal_api/devices_for_user/%d/" % device_id,
            headers={
                'Authorization': "Bearer " + token
            },
            json={
                'name': form.cleaned_data['name'],
                'type_of_device': form.cleaned_data['type_of_device']
            }
        )
        if response.status_code not in [200, 201]:
            raise Exception("Error in connection with AuthService: "
                            + response.text)
