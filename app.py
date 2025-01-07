from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session
from scanner.zap_scanner import ZAPScanner
from generate_reports.report_generator import generate_pdf_report
import os
import json
import threading
import time
import uuid
from datetime import datetime
from config.settings import FOLDER_PATH

app = Flask(__name__, template_folder=FOLDER_PATH)
app.secret_key = "web-scanner"

PDF_FOLDER = "public/reports"
os.makedirs(PDF_FOLDER, exist_ok=True)
TEMP_FOLDER = "temp"
os.makedirs(TEMP_FOLDER, exist_ok=True)

schedules = []

def get_safe_filename(url, scan_type):
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    filename = url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
    return f"{filename} - vulnerability_report - {scan_type} ({current_datetime})"

def sort_alerts_by_risk(alerts):
    risk_order = {"High": 1, "Medium": 2, "Low": 3, "Informational": 4}

    sorted_alerts = sorted(alerts, key=lambda alert: risk_order.get(alert.get("risk", "Informational"), 5))
    return sorted_alerts

#for scheduled scan
def perform_scan(target_url, scan_type):
    scanner = ZAPScanner(target_url, scan_type)
    alerts = scanner.run_scan()

    sorted_alerts = sort_alerts_by_risk(alerts)

    pdf_filename = get_safe_filename(target_url, scan_type)+".pdf"
    pdf_path = os.path.join(PDF_FOLDER, pdf_filename)

    generate_pdf_report(alerts=sorted_alerts, output_file=pdf_path, target_url=target_url)

    print(f"Scan completed and report saved as {pdf_path}")

# Start the background thread to check the schedule
def start_schedule_thread():
    thread = threading.Thread(target=check_schedule, daemon=True)
    thread.start()

def check_schedule():
    """Function will check the scheduled time and triggers the scan when the time matches."""
    while True:
        current_time = datetime.now()

        for schedule in schedules:
            try:
                scheduled_time = datetime.strptime(schedule["datetime"], "%Y-%m-%dT%H:%M")

                if current_time >= scheduled_time:
                    print(f"Scheduled scan for {schedule['target_url']} at {schedule['datetime']} is now triggered.")
                    
                    scan_thread_instance = threading.Thread(target=perform_scan, args=(schedule["target_url"], schedule["scan_type"]))
                    scan_thread_instance.start()

                    schedules.remove(schedule)
            except ValueError as e:
                print(f"Error parsing scheduled datetime: {schedule['datetime']} - {e}")

        time.sleep(60)

@app.route("/", methods=["GET", "POST"])
def dashboard():
    if request.method == "POST":
        target_url = request.form["target_url"]
        scan_type = request.form["scan_type"]
        
        scanner = ZAPScanner(target_url, scan_type)
        alerts = scanner.run_scan()

        sorted_alerts = sort_alerts_by_risk(alerts)

        unique_id = str(uuid.uuid4())
        temp_file_path = os.path.join(TEMP_FOLDER, f"{unique_id}.json")
        with open(temp_file_path, "w") as file:
            json.dump(sorted_alerts, file)

        pdf_filename = get_safe_filename(target_url, scan_type)+".pdf"
        pdf_path = os.path.join(PDF_FOLDER, pdf_filename)

        generate_pdf_report(alerts=sorted_alerts, output_file=pdf_path, target_url=target_url)

        #PDF URL
        pdf_url = f"/reports/{pdf_filename}"

        # Redirect to show results
        return redirect(url_for("view_report", report_id=unique_id, pdf_url=pdf_url))

    return render_template("dashboard.html")

@app.route("/report")
def view_report():
    report_id = request.args.get("report_id")
    pdf_url = request.args.get("pdf_url")
    temp_file_path = os.path.join(TEMP_FOLDER, f"{report_id}.json")

    alerts = []
    if(report_id):
        if os.path.exists(temp_file_path):
            with open(temp_file_path, "r") as file:
                alerts = json.load(file)
        
        os.remove(temp_file_path)
    else:
        alerts = []

    return render_template("report.html", alerts=alerts, pdf_url=pdf_url)

@app.route("/schedule_scan", methods=["POST"])
def schedule_scan():
    if request.method == "POST":
        target_url = request.form["target_url"]
        scan_type = request.form["scan_type"]
        scheduled_datetime = request.form["scheduled_datetime"]
    
        schedules.append({
            "target_url": target_url,
            "scan_type": scan_type,
            "datetime": scheduled_datetime
        })
    
        return redirect(url_for('schedule_success', target_url=target_url, scan_type=scan_type, scheduled_datetime=scheduled_datetime))

@app.route("/success")
def schedule_success():
    target_url = request.args.get("target_url")
    scan_type = request.args.get("scan_type")
    scheduled_datetime = request.args.get("scheduled_datetime")
    
    return render_template("schedule_success.html", target_url=target_url, scan_type=scan_type, scheduled_datetime=scheduled_datetime)

@app.route("/reports")
def list_reports():
    reports = [f for f in os.listdir(PDF_FOLDER) if f.endswith('.pdf')]
    return render_template("reports.html", reports=reports)

@app.route("/reports/<filename>")
def serve_report(filename):
    return send_from_directory(PDF_FOLDER, filename)

if __name__ == "__main__":
    start_schedule_thread()
    app.run(debug=True, use_reloader=False)
