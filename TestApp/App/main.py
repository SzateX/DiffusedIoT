from kivy.app import App
from kivy.properties import StringProperty, NumericProperty, BooleanProperty
from kivy.uix.gridlayout import GridLayout
from kivy.uix.widget import Widget


class ValuesWidget(GridLayout):
    title = StringProperty("None")
    current = NumericProperty(0)
    setted = NumericProperty(0)
    activated = BooleanProperty(False)


class IoTWidget(Widget):
    new_value = StringProperty("50")
    device = StringProperty("Raspberry")

    def send_data_callback(self):
        print(self.new_value)
        print(self.device)


class IoTApp(App):
    def build(self):
        return IoTWidget()


if __name__ == '__main__':
    IoTApp().run()
