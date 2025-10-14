from django.http import HttpResponse
import os
def simple_test(request):
    return HttpResponse('Django is working!')
