import json
import threading
from time import sleep
import RPi.GPIO as GPIO
import paho.mqtt.client as mqtt

def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("inzynierkav2/sender")

letters = [10, 9, 1, 4, 3, 6, 5]
mux = [8, 7]

digits = [
    (1, 1, 1, 1, 1, 1, 0),
    (0, 1, 1, 0, 0, 0, 0),
    (1, 1, 0, 1, 1, 0, 1),
    (1, 1, 1, 1, 0, 0, 1),
    (0, 1, 1, 0, 0, 1, 1),
    (1, 0, 1, 1, 0, 1, 1),
    (1, 0, 1, 1, 1, 1, 1),
    (1, 1, 1, 0, 0, 0, 0),
    (1, 1, 1, 1, 1, 1, 1),
    (1, 1, 1, 1, 0, 1, 1),
]

number = 0
stop = False


def on_message(client, userdata, msg):
    global number
    try:
        payload = json.dumps(msg.payload.decode("utf-8"))
        if payload['device'] == 1:
            number = payload['data']['temperature']
    except Exception as e:
        print(e)


def display():
    n1 = number % 10
    n2 = int(number / 10) % 10
    GPIO.output(letters, digits[n1])
    GPIO.output(mux[1], 1)
    sleep(0.001)
    GPIO.output(mux[1], 0)
    GPIO.output(letters, digits[n2])
    GPIO.output(mux[0], 1)
    sleep(0.001)
    GPIO.output(mux[0], 0)


def t():
    while not stop:
        display()


if __name__ == "__main__":
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(letters, GPIO.OUT, initial=0)
    GPIO.setup(mux, GPIO.OUT, initial=0)
    x = threading.Thread(target=t)
    x.start()

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect("test.mosquitto.org", 1883, 60)
    try:
        client.loop_forever()
    except KeyboardInterrupt:
        stop = True

