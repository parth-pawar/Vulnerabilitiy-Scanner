<<<<<<< HEAD
# Vulnerability Scanner Tool

This is a locally hosted web application that integrates with [OWASP ZAP](https://www.zaproxy.org/) to scan websites for a variety of vulnerabilities. It provides different scan types (Spider, Active, Passive, SQL Injection, XSS, and more) and generates comprehensive reports categorizing vulnerabilities by severity.

## Features
- **Scan Types**: 
  - Spider Scan
  - Active Scan
  - Passive Scan
  - SQL Injection
  - XSS Scan
  - AJAX Spider

- **Scan Scheduling**: Option to schedule scans for later execution.
- **Detailed Reports**: Automatically generates reports categorizing vulnerabilities by risk level (High, Medium, Low, Informational).
- **View Reports**: Option to view detailed vulnerability scan reports in both HTML and PDF formats.


## Installation

### Prerequisites
Before setting up this tool, ensure you have the following installed:
- [Python 3](https://www.python.org/downloads/)
- [OWASP ZAP](https://www.zaproxy.org/) 

### Steps
1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/vulnerability-scanner-tool.git
    cd vulnerability-scanner-tool
    ```

2. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Configure OWASP ZAP**:
    - Download and install [OWASP ZAP](https://www.zaproxy.org/download/) on your local machine.
    - Ensure ZAP is running and accessible via API (`localhost:8080` by default).

4. **Start the application**:
    ```bash
    python app.py  
    ```
    This will start the tool on `http://localhost:5000` (default Flask port).

## Usage
1. **Start a Scan**: 
   - Enter the target URL and select the scan type.
   - Click "Start Scan" to initiate the scan.

2. **Schedule a Scan**: 
   - Check the "Schedule Scan" option and select a date and time.
   - Click "Schedule Scan" to set the scan for later execution.

3. **View Reports**: 
   - Navigate to the "Reports" section to view detailed vulnerability reports after scanning.
   - You can view and download the reports in PDF format.

## Files & Structure
- **app.py**: Main script for running the application.
- **/generate_reports/report_generator.py**: PDF report generating logic.
- **/scanner/zap_scanner.py**: Scanning methods.
- **/public**: HTML templates for the web interface.
  - **/public/dashboard.html**: Main interface for initiating scans.
  - **/public/report.html**: Displays detailed vulnerability report after scan completion.
  - **/public/reports.html**: Displays all available reports.
  - **/public/schedule_success.html**: Confirms successful scan scheduling.
- **requirements.txt**: List of required Python dependencies for the application.

=======
# Vulnerabilitiy-Scanner
>>>>>>> 8bbc2d98ab51266b6d673212393f417c2966003b
