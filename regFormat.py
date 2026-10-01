import re

IP_FLEXIBLE = r'(?P<ip>(?:[\d.]{7,15}|[0-9A-Fa-f:\[\]]{3,45}))'

PATTERNS = [
    # SSH/System Logs (Linux/Unix)
    ("ssh_failed_password", re.compile(r"Failed password for (?:invalid user )?.* from " + IP_FLEXIBLE)),
    ("ssh_invalid_user", re.compile(r"Invalid user .* from " + IP_FLEXIBLE)),
    ("pam_auth_failure_rhost", re.compile(r"pam_unix.*rhost=" + IP_FLEXIBLE)),
    ("sudo_auth_failure_rhost", re.compile(r"sudo:.*authentication failure.*rhost=" + IP_FLEXIBLE)),
    ("ssh_too_many_auth", re.compile(r"error: maximum authentication attempts exceeded for .* from " + IP_FLEXIBLE)),
    
    # Web Server/WAF Logs (Apache/Nginx/ModSecurity)
    ("apache_401_auth_fail", re.compile(r"^" + IP_FLEXIBLE + r" - .*\"[A-Z]+ .*\" 401 \d+")),
    ("modsecurity_denial", re.compile(r"\[client\s+" + IP_FLEXIBLE + r"\].*ModSecurity: Access denied")),
    
    # Windows/Service Logs (General)
    ("win_event_failed_logon", re.compile(r"(?:Logon Failure|Event ID: 4625).*?(?:Source Network Address|ClientIP|Client Address):\s*" + IP_FLEXIBLE)),

    # FTP/Mail/Cisco Logs
    ("ftp_vsftpd_fail", re.compile(r"FAIL LOGIN: client=" + IP_FLEXIBLE)),
    ("mail_dovecot_rip", re.compile(r"dovecot.*rip=" + IP_FLEXIBLE)),
    ("cisco_login_failed", re.compile(r"Login failed.*ip " + IP_FLEXIBLE)),
    
    # Catch-All Generic Patterns
    ("simple_login_fail_prefix", re.compile(IP_FLEXIBLE + r".*login failed")),
    
    # Catch-all pattern for common failure keywords
    ("generic_failed_login", re.compile(
        r"(?i)(failed|unauthorized|authentication failure|login error).*from " + IP_FLEXIBLE
    ))
]