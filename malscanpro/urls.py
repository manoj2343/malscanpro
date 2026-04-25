from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import redirect

urlpatterns = [
    path('admin/', admin.site.urls),

    # Default redirect from root to file-scan
    path('', lambda request: redirect('scan_combined'), name='home'),

    # Include scanner app urls
    path('', include('scanner.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
