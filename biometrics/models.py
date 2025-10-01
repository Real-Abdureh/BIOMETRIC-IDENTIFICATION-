from django.db import models
from django.contrib.auth.models import User

class FaceData(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    face_token = models.CharField(max_length=255)
    fullname = models.CharField(max_length=255, blank=True, null=True)
    registration_number = models.CharField(max_length=50, unique=True, blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    level = models.CharField(max_length=50, blank=True, null=True)
    state_of_origin = models.CharField(max_length=100, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.fullname} ({self.registration_number})"




class WebAuthnCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    credential_id = models.TextField(unique=True)   # Base64 encoded credential ID
    public_key = models.TextField()                # Base64 encoded public key
    sign_count = models.IntegerField(default=0)    # Signature counter
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.credential_id[:10]}..."
