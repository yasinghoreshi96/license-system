from django.urls import path
from .views import generate_license, validate_license

urlpatterns = [
    path('generate_license/', generate_license, name='generate_license'),
    path('validate_license/', validate_license, name='validate_license'),
]
