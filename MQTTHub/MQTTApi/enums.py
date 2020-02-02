class DeviceType:
    GENERIC_TEMPERATURE_SENSOR = 'GTS'
    GENERIC_HUMIDITY_SENSOR = 'GHS'
    GENERIC_LAMP = 'GL'


class UnitDirection:
    INPUT = 'input'
    OUTPUT = 'output'
    IN_OUT = 'inout'


class UnitType:
    SWITCH_UNIT = 'switch'
    TEMPERATURE_UNIT = 'temperature'
    HUMIDITY_UNIT = 'humidity'
    UNKNOWN_UNIT = 'unknown'


class TemperatureUnit:
    CELSIUS = 'celsius'
    KELVIN = 'kelvin'
    FAHRENHEIT = 'fahrenheit'


class HumidityUnit:
    PERCENTAGE = 'percentage'
    GRAMS_PER_METER_SQUARED = 'grams per meter squared'