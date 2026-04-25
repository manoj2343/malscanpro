import os
import csv
import time
import yara
import requests
from io import BytesIO
from urllib.parse import urlparse
from django.conf import settings
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from django.utils.timezone import localtime
from .forms import FileUploadForm, URLScanForm
from .models import ScanReport
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from django.contrib.auth.decorators import login_required




def get_client_ip(request):
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded.split(',')[0] if x_forwarded else request.META.get('REMOTE_ADDR')


def load_yara_rules():
    yara_path = os.path.join(settings.BASE_DIR, 'scanner', 'yara_rules.yar')
    if not os.path.exists(yara_path):
        return None, f"⚠️ YARA rules file not found at: {yara_path}"
    try:
        rules = yara.compile(filepath=yara_path)
        return rules, None
    except yara.SyntaxError as e:
        return None, f"⚠️ Error in YARA rule syntax: {e}"
    except Exception as e:
        return None, f"⚠️ Failed to load YARA rules: {e}"


def scan_file(filepath):
    rules, error = load_yara_rules()
    if not rules:
        return None, error
    try:
        return rules.match(filepath), None
    except yara.Error as e:
        return None, f"⚠️ Error while scanning file: {e}"


def recommend_solution(matches):
    solutions = {
        'SuspiciousPowerShell': 'Avoid running untrusted PowerShell scripts.',
        'PossibleKeylogger': 'Check for keylogger processes using Task Manager.',
        'SuspiciousPDFScript': 'Avoid opening suspicious PDF files with embedded JavaScript.',
        'Ransomware_Locky': 'Restore from backup and clean the system with antivirus.',
        'Ransomware_WannaCry': 'Patch system vulnerabilities and restore files from backup.',
        'Ransomware_Ryuk': 'Disconnect affected systems and report to security team.',
        'Suspicious_JavaScript_Obfuscation': 'Avoid visiting sites with heavily obfuscated scripts.',
        'URL_Phishing_Detected': 'Never enter sensitive data on suspicious URLs.',
        'Suspicious_IFRAME_Usage': 'Avoid unknown links that embed iframe scripts.',
        'Powershell_Dropper': 'Disable PowerShell unless needed and scan with antivirus.',
        'Common_Malware_Hosts': 'Don’t download or run files from suspicious domains.',
    }
    return [solutions.get(m.rule, 'Delete the file or run a full antivirus scan.') for m in matches]

def scan_view(request):
    file_form = FileUploadForm()
    url_form = URLScanForm()
    result = None
    suggestions = []
    report_id = None
    scan_duration = None
    file_error = url_error = None
    active_tab = 'file'

    if request.method == 'POST':
        ip_address = get_client_ip(request)
        scan_type = request.POST.get('scan_type')

        # File Scan
        if scan_type == 'file':
            active_tab = 'file'
            file_form = FileUploadForm(request.POST, request.FILES)
            if file_form.is_valid():
                uploaded_file = request.FILES.get('file')
                if uploaded_file:
                    file_name = os.path.basename(uploaded_file.name)
                    upload_path = os.path.join(settings.MEDIA_ROOT, file_name)

                    with open(upload_path, 'wb+') as destination:
                        for chunk in uploaded_file.chunks():
                            destination.write(chunk)

                    start = time.time()
                    matches, yara_error = scan_file(upload_path)
                    scan_duration = round(time.time() - start, 2)

                    if yara_error:
                        file_error = yara_error
                    else:
                        result = [m.rule for m in matches] if matches else None
                        suggestions = recommend_solution(matches) if matches else []

                        report = ScanReport.objects.create(
                            file_name=file_name,
                            malware_detected=bool(matches),
                            matched_rules=', '.join(result) if matches else '',
                            recommendations='\n'.join(suggestions) if matches else '',
                            ip_address=ip_address
                        )
                        report_id = report.id
                else:
                    file_error = "No file was uploaded."

        # URL Scan
        elif scan_type == 'url':
            active_tab = 'url'
            url_form = URLScanForm(request.POST)
            if url_form.is_valid():
                url = url_form.cleaned_data.get('url')
                try:
                    parsed_url = urlparse(url)
                    if not parsed_url.scheme.startswith('http'):
                        raise ValueError("Invalid URL format")

                    headers = {
                        'User-Agent': 'Mozilla/5.0',
                        'Accept': '*/*',
                        'Connection': 'keep-alive'
                    }

                    response = requests.get(url, headers=headers, timeout=10)

                    if response.status_code != 200:
                        url_error = f"URL scan failed: HTTP {response.status_code}"
                    else:
                        file_name = parsed_url.path.split("/")[-1] or "url_scan.txt"
                        upload_path = os.path.join(settings.MEDIA_ROOT, file_name)

                        with open(upload_path, 'wb') as f:
                            f.write(response.content)

                        start = time.time()
                        matches, yara_error = scan_file(upload_path)
                        scan_duration = round(time.time() - start, 2)

                        if yara_error:
                            url_error = yara_error
                        else:
                            result = [m.rule for m in matches] if matches else None
                            suggestions = recommend_solution(matches) if matches else []

                            report = ScanReport.objects.create(
                                file_name=file_name,
                                malware_detected=bool(matches),
                                matched_rules=', '.join(result) if matches else '',
                                recommendations='\n'.join(suggestions) if matches else '',
                                ip_address=ip_address,
                                user=request.user if request.user.is_authenticated else None
                            )
                            report_id = report.id
                except Exception as e:
                    url_error = f"URL scan failed: {e}"

    return render(request, 'scanner/scan_combined.html', {
        'file_form': file_form,
        'url_form': url_form,
        'result': result,
        'suggestions': suggestions,
        'report_id': report_id,
        'scan_duration': scan_duration,
        'file_error': file_error,
        'url_error': url_error,
        'active_tab': active_tab,
    })

@login_required
def export_single_csv(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id)
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="scan_report_{report_id}.csv"'

    writer = csv.writer(response)
    writer.writerow(['File Name', 'Upload Time', 'Malware Detected', 'Matched Rules', 'Recommendations'])
    writer.writerow([
        report.file_name,
        localtime(report.upload_time).strftime("%d %b %Y, %I:%M %p"),
        'Yes' if report.malware_detected else 'No',
        report.matched_rules,
        report.recommendations
    ])
    return response

@login_required
def export_single_pdf(request, report_id):
    report = get_object_or_404(ScanReport, pk=report_id)
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    p.setFont("Helvetica-Bold", 14)
    p.drawString(180, height - 50, "MalScanPro - Report")

    y = height - 100
    p.setFont("Helvetica", 10)
    p.drawString(40, y, f"File Name: {report.file_name}")
    y -= 15
    p.drawString(40, y, f"Upload Time: {localtime(report.upload_time).strftime('%d %b %Y, %I:%M %p')}")
    y -= 15
    p.drawString(40, y, f"Malware Detected: {'Yes' if report.malware_detected else 'No'}")
    y -= 15
    p.drawString(40, y, f"Matched Rules: {report.matched_rules}")
    y -= 15
    p.drawString(40, y, f"Recommendations: {report.recommendations}")

    p.save()
    buffer.seek(0)
    return HttpResponse(buffer, content_type='application/pdf')


from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from .forms import RegisterForm, LoginForm

def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # 👈 log the user in immediately
            return redirect("scan_view")  # 👈 redirect to scan page
    else:
        form = RegisterForm()
    return render(request, "register.html", {"form": form})

def login_view(request):
    if request.method == "POST":
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect("scan_view")
    else:
        form = LoginForm()
    return render(request, "login.html", {"form": form})

def logout_view(request):
    logout(request)
    return redirect("login")
