from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter

def generate_pdf_report(alerts, output_file, target_url):
    # Create the PDF document
    doc = SimpleDocTemplate(output_file, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Add title
    title = Paragraph("<b>Vulnerability Scan Report</b>", styles["Title"])
    elements.append(title)
    elements.append(Spacer(1, 12))

    # Add scanned URL
    scanned_url_paragraph = Paragraph(f"<b>Scanned URL:</b> {target_url}", styles["Normal"])
    elements.append(scanned_url_paragraph)
    elements.append(Spacer(1, 12))

    # Add vulnerabilities
    for i, alert in enumerate(alerts, start=1):
        alert_title = Paragraph(f"<b>{i}. {alert['alert']}</b>", styles["Heading2"])
        elements.append(alert_title)
        elements.append(Spacer(1, 12))

        severity = Paragraph(f"<b>Severity:</b> {alert['risk']}", styles["Normal"])
        elements.append(severity)
        elements.append(Spacer(1, 12))

        description = Paragraph(f"<b>Description:</b> {alert['description']}", styles["Normal"])
        elements.append(description)
        elements.append(Spacer(1, 12))

        solution = Paragraph(f"<b>Solution:</b> {alert['solution']}", styles["Normal"])
        elements.append(solution)
        elements.append(Spacer(1, 12))

        url = Paragraph(f"<b>URL:</b> {alert['url']}", styles["Normal"])
        elements.append(url)
        elements.append(Spacer(1, 24)) 

    doc.build(elements)
    print(f"Report saved as {output_file}")
