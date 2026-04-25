from django.contrib import admin
from .models import ScanReport

@admin.register(ScanReport)
class ScanReportAdmin(admin.ModelAdmin):
    list_display = ("file_name", "user", "upload_time", "malware_detected")
    search_fields = ("file_name", "matched_rules", "user__username", "user__email")
    list_filter = ("malware_detected",)




# scanner/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, ScanReport

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ("username", "email", "is_staff", "is_active")
    list_filter = ("is_staff", "is_superuser", "is_active", "groups")
    search_fields = ("username", "email")
    ordering = ("username",)
