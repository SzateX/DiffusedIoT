from django import template
import datetime
import dateutil.parser

register = template.Library()


def from_iso(value):
    return dateutil.parser.parse(value)
    #return datetime.datetime.fromisoformat(value)


register.filter('from_iso', from_iso)
