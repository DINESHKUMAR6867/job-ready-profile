from django.urls import path
from scoring.simple_test import simple_test
urlpatterns = [
    path('', simple_test, name='home'),
    path('test/', simple_test, name='test'),
]
