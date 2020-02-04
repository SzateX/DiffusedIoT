import json

import paho.mqtt.client as mqtt


def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect_async("test.mosquitto.org", 1883, 60)
client.loop_start()

while True:
    t = int(input("Wprowadz liczbę:"))
    r = client.publish('DiffusedIoT/listener', payload=json.dumps({
        'device': 14,
        'unit': 9,
        'data': {'temperature': t}
    }))
    print(r)
