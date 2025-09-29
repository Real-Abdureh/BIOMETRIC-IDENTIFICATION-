from django.db import models
from django.contrib.auth.models import User

class FaceData(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    face_token = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"FaceData({self.user.username})"



class WebAuthnCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    credential_id = models.TextField(unique=True)   # Base64 encoded credential ID
    public_key = models.TextField()                # Base64 encoded public key
    sign_count = models.IntegerField(default=0)    # Signature counter
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.credential_id[:10]}..."
