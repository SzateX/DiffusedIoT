import json

from kivy.app import App
from kivy.properties import StringProperty, NumericProperty, BooleanProperty, \
    ObjectProperty
from kivy.uix.gridlayout import GridLayout
from kivy.uix.widget import Widget
import paho.mqtt.client as mqtt
from kivy.clock import mainthread


def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("DiffusedIoT/sender")


def on_disconnect(*args, **kwargs):
    print(args)
    print(kwargs)
    print("DISCONNECTED")


def mqtt_callback(client, userdata, msg):
    print(msg)
    decoded_msg = json.loads(msg.payload)
    if decoded_msg['device'] == 13:
        if decoded_msg['unit'] == 7:
            userdata['widget'].raspberry_values.setted = decoded_msg['data']['temperature']
        elif decoded_msg['unit'] == 8:
            userdata['widget'].raspberry_values.current = decoded_msg['data']['temperature']
    elif decoded_msg['device'] == 14:
        if decoded_msg['unit'] == 9:
            userdata['widget'].beaglebone_values.setted = decoded_msg['data']['temperature']
        elif decoded_msg['unit'] == 10:
            userdata['widget'].beaglebone_values.current = decoded_msg['data']['temperature']
    elif decoded_msg['device'] == 15:
        if decoded_msg['unit'] == 11:
            userdata['widget'].raspberry_values.activated = decoded_msg['data']['state']
    elif decoded_msg['device'] == 16:
        if decoded_msg['unit'] == 12:
            userdata['widget'].beaglebone_values.activated = decoded_msg['data']['state']



class ValuesWidget(GridLayout):
    title = StringProperty("None")
    current = NumericProperty(0)
    setted = NumericProperty(0)
    activated = BooleanProperty(False)


class IoTWidget(Widget):
    new_value = StringProperty("50")
    device = StringProperty("Raspberry")
    raspberry_values = ObjectProperty(None)
    beaglebone_values = ObjectProperty(None)

    def send_data_callback(self):
        client = App.get_running_app().client
        r = client.publish('DiffusedIoT/listener', payload=json.dumps({
            'device': 13 if self.device is "Raspberry" else 14,
            'unit': 7 if self.device is "Raspberry" else 9,
            'data': {'temperature': self.new_value}
        }))
        print(r.rc == mqtt.MQTT_ERR_SUCCESS)
        print(r.is_published())


class IoTApp(App):
    def build(self):
        iot_widget = IoTWidget()
        self.client = mqtt.Client(userdata={'widget': iot_widget})
        # self.client = mqtt.Client()
        self.client.on_connect = on_connect
        self.client.on_message = mqtt_callback
        self.client.on_disconnect = on_disconnect
        self.client.on_log = lambda *x, **y: (print(x), print(y))
        self.client.connect("test.mosquitto.org", 1883, 60)
        self.client.enable_logger()
        self.client.loop_start()
        return iot_widget


if __name__ == '__main__':
    IoTApp().run()
