from django.urls import path
from . import views

app_name = 'biometrics'
urlpatterns = [
    path('enroll/face/', views.enroll_face, name='enroll_face'),
    path('verify/', views.verify_face, name='verify_face'),

     path('fingerprint/start-enroll/', views.start_fingerprint_enroll, name='start_fingerprint_enroll'),
    path('fingerprint/complete-enroll/', views.complete_fingerprint_enroll, name='complete_fingerprint_enroll'),
    path('fingerprint/start-verify/', views.start_fingerprint_verify, name='start_fingerprint_verify'),
    path('fingerprint/complete-verify/', views.complete_fingerprint_verify, name='complete_fingerprint_verify'),
]
