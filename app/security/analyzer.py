import re
import ast

class SecurityAnalyzer:
    """Analyzes code for security smells and vulnerabilities"""
    
    def __init__(self, code, language='python'):
        self.code = code
        self.language = language
        self.issues = []
        self.score = 100  # Start with 100, deduct for each issue
    
    def analyze(self):
        """Run all security checks based on language"""
        if self.language == 'python':
            self.analyze_python()
        elif self.language == 'javascript':
            self.analyze_javascript()
        else:
            self.analyze_generic()
        
        # Calculate final score (minimum 0)
        self.score = max(0, self.score)
        return {
            'issues': self.issues,
            'score': self.score,
            'has_issues': len(self.issues) > 0,
            'severity': self.get_severity()
        }
    
    def analyze_python(self):
        """Python-specific security checks"""
        
        # Check for hardcoded passwords/secrets
        secret_patterns = [
            (r'password\s*=\s*[\'"][^\'"]+[\'"]', 'Hardcoded password detected'),
            (r'api_key\s*=\s*[\'"][^\'"]+[\'"]', 'Hardcoded API key detected'),
            (r'secret\s*=\s*[\'"][^\'"]+[\'"]', 'Hardcoded secret detected'),
            (r'token\s*=\s*[\'"][^\'"]+[\'"]', 'Hardcoded token detected'),
        ]
        
        for pattern, message in secret_patterns:
            if re.search(pattern, self.code, re.IGNORECASE):
                self.issues.append({'type': 'Hardcoded Secret', 'message': message, 'severity': 'High'})
                self.score -= 20
        
        # Check for eval/exec usage
        if re.search(r'\beval\s*\(', self.code):
            self.issues.append({'type': 'Code Injection', 'message': 'eval() usage allows arbitrary code execution', 'severity': 'Critical'})
            self.score -= 30
        
        if re.search(r'\bexec\s*\(', self.code):
            self.issues.append({'type': 'Code Injection', 'message': 'exec() usage allows arbitrary code execution', 'severity': 'Critical'})
            self.score -= 30
        
        # Check for command injection
        if re.search(r'subprocess\.', self.code) and 'shell=True' in self.code:
            self.issues.append({'type': 'Command Injection', 'message': 'subprocess with shell=True is dangerous', 'severity': 'High'})
            self.score -= 25
        
        # Check for SQL injection (string concatenation)
        if re.search(r'"\s*\+\s*"', self.code) and ('SELECT' in self.code.upper() or 'INSERT' in self.code.upper()):
            self.issues.append({'type': 'SQL Injection', 'message': 'String concatenation in SQL query - use parameters', 'severity': 'Critical'})
            self.score -= 35
        
        # Check for pickle usage
        if re.search(r'\bpickle\.', self.code):
            self.issues.append({'type': 'Insecure Deserialization', 'message': 'pickle is unsafe for untrusted data', 'severity': 'High'})
            self.score -= 20
        
        # Check for assert usage for security
        if re.search(r'\bassert\s+.*(user|admin|permission|role)', self.code, re.IGNORECASE):
            self.issues.append({'type': 'Insecure Assertion', 'message': 'assert is disabled in optimized mode', 'severity': 'Medium'})
            self.score -= 10
        
        # Check for debug mode
        if 'debug=True' in self.code or 'DEBUG = True' in self.code:
            self.issues.append({'type': 'Debug Mode', 'message': 'Debug mode enabled in production', 'severity': 'Medium'})
            self.score -= 15
    
    def analyze_javascript(self):
        """JavaScript-specific security checks"""
        
        # Check for eval
        if re.search(r'\beval\s*\(', self.code):
            self.issues.append({'type': 'Code Injection', 'message': 'eval() usage is dangerous', 'severity': 'Critical'})
            self.score -= 30
        
        # Check for innerHTML (XSS risk)
        if re.search(r'\.innerHTML\s*=', self.code):
            self.issues.append({'type': 'XSS Risk', 'message': 'innerHTML can lead to XSS attacks', 'severity': 'High'})
            self.score -= 20
        
        # Check for hardcoded secrets
        if re.search(r'(api[_-]?key|secret|password|token)\s*[:=]\s*[\'"][^\'"]+[\'"]', self.code, re.IGNORECASE):
            self.issues.append({'type': 'Hardcoded Secret', 'message': 'Hardcoded credential detected', 'severity': 'High'})
            self.score -= 20
        
        # Check for document.write (XSS risk)
        if re.search(r'document\.write\s*\(', self.code):
            self.issues.append({'type': 'XSS Risk', 'message': 'document.write can lead to XSS', 'severity': 'Medium'})
            self.score -= 15
    
    def analyze_generic(self):
        """Generic security checks for any language"""
        
        # Check for hardcoded secrets (generic)
        generic_secrets = [
            (r'(password|passwd)\s*=\s*[\'"][^\'"]+[\'"]', 'Hardcoded password'),
            (r'(api[_-]?key|apikey)\s*=\s*[\'"][^\'"]+[\'"]', 'Hardcoded API key'),
            (r'(secret|token)\s*=\s*[\'"][^\'"]+[\'"]', 'Hardcoded secret/token'),
        ]
        
        for pattern, message in generic_secrets:
            if re.search(pattern, self.code, re.IGNORECASE):
                self.issues.append({'type': 'Hardcoded Secret', 'message': message, 'severity': 'High'})
                self.score -= 20
        
        # Check for potential command execution
        if re.search(r'(exec|system|shell_exec|popen)\s*\(', self.code, re.IGNORECASE):
            self.issues.append({'type': 'Command Injection', 'message': 'Command execution function detected', 'severity': 'High'})
            self.score -= 25
    
    def get_severity(self):
        """Return overall severity level"""
        if not self.issues:
            return 'Safe'
        critical_count = sum(1 for i in self.issues if i['severity'] == 'Critical')
        high_count = sum(1 for i in self.issues if i['severity'] == 'High')
        
        if critical_count > 0:
            return 'Critical'
        elif high_count > 0:
            return 'High'
        else:
            return 'Medium'