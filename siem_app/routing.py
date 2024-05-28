from django.urls import re_path
from .consumers import RealTimeAnalysisConsumer

websocket_urlpatterns = [
    re_path(r'ws/real-time-analysis/$', RealTimeAnalysisConsumer),
]
