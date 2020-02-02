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

client.connect("test.mosquitto.org", 1883, 60)
client.loop_start()

while True:
    t = int(input("Wprowadz liczbę:"))
    client.publish('inzynierkav2/listener', payload=json.dumps({
        'device': 11,
        'unit': 4,
        'data': {'temperature': t}
    }))
