from django.db import models

class License(models.Model):
    license_id = models.CharField(max_length=255, unique=True)
    encrypted_message = models.BinaryField()
    usage_count = models.IntegerField(default=0) 
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.license_id
