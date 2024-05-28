from .core import ModelMixin
from django.db import models

class SecurityEvent(ModelMixin):
    source_ip = models.CharField(max_length=15)
    destination_ip = models.CharField(max_length=15)
    event_type = models.CharField(max_length=50)
    raw_data = models.TextField()