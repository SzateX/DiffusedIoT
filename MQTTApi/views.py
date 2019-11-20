from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.views.generic import FormView


class HubLoginView(FormView):
    def form_valid(self, form):
        raise NotImplementedError()
        # return HttpResponseRedirect(self.get_success_url())
