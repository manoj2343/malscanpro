# from django.urls import path
# from .views import scan_view
# from . import views

# urlpatterns = [
#     path('', scan_view, name='scan'),
#     path('export/single/csv/<int:report_id>/', views.export_single_csv, name='export_single_csv'),
#     path('export/single/pdf/<int:report_id>/', views.export_single_pdf, name='export_single_pdf'),
# ]

from django.urls import path
from . import views

urlpatterns = [
    # path('file-scan/', views.scan_view, name='scan_combined'),
    # path('url-scan/', views.url_scan_view, name='url_scan'),
    path('file-scan/', views.scan_view, name='scan_combined'),
    path('file-scan-alias/', views.scan_view, name='scan_view'),
    path('', views.scan_view, name='scan'),  # 👈 main scan view
    path('download/csv/<int:report_id>/', views.export_single_csv, name='export_single_csv'),
    path('download/pdf/<int:report_id>/', views.export_single_pdf, name='export_single_pdf'),
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    # path('', views.scan_view, name='scan_view')

]
