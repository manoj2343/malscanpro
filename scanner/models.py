from django.db import models
from django.utils import timezone
from django.conf import settings

class ScanReport(models.Model):
    file_name = models.CharField(max_length=255)
    upload_time = models.DateTimeField(default=timezone.now)
    malware_detected = models.BooleanField()
    matched_rules = models.TextField(blank=True)  # Comma-separated rules
    recommendations = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user = models.ForeignKey(
    settings.AUTH_USER_MODEL,
    null=True,
    blank=True,
    on_delete=models.SET_NULL,
    related_name="scan_reports"
    )

    def __str__(self):
        return f"{self.file_name} - {self.upload_time}"
    

    # def __str__(self):
    #     return f"{self.file_name} - {'Malware' if self.malware_detected else 'Clean'}"


from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)

    def __str__(self):
        return self.username
