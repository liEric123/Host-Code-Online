from flask import Flask, render_template, request, jsonify
import requests
import re
import random
import string
import json
import autopep8
import jsbeautifier
from bs4 import BeautifulSoup

app = Flask(__name__)

class RentryUploader:
    def __init__(self):
        self.base_url = "https://rentry.co"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
    
    def get_csrf_token(self, url=None):
        """Get CSRF token from rentry.co page"""
        try:
            # Go to the specified page or main page to get the form
            target_url = url if url else self.base_url
            response = self.session.get(target_url)
            response.raise_for_status()
            
            # Extract CSRF token from the form
            csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]*)"', response.text)
            if csrf_match:
                return csrf_match.group(1)
            
            return None
        except Exception as e:
            print(f"Error getting CSRF token: {e}")
            return None
    
    def generate_random_string(self, length=8):
        """Generate random string for URL if not provided"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def extract_url_slug(self, url_input):
        """Extract just the slug from a full rentry.co URL"""
        if not url_input:
            return None
        
        url_input = url_input.strip()
        
        # Remove protocol if present
        if url_input.startswith('https://'):
            url_input = url_input[8:]
        elif url_input.startswith('http://'):
            url_input = url_input[7:]
        
        # Remove rentry.co domain if present
        if url_input.startswith('rentry.co/'):
            url_input = url_input[10:]
        elif url_input.startswith('www.rentry.co/'):
            url_input = url_input[14:]
        
        # Remove trailing slash if present
        if url_input.endswith('/'):
            url_input = url_input[:-1]
        
        # Return the slug (should just be the URL identifier now)
        return url_input if url_input else None
    
    def check_url_availability(self, url):
        """Check if a custom URL is already taken"""
        try:
            response = self.session.get(f"{self.base_url}/{url}")
            # If we get 200, the URL exists (taken)
            # If we get 404, the URL is available
            return response.status_code == 404
        except Exception:
            # If there's an error checking, assume it's available
            return True

    def upload_code(self, code_text, custom_url=None, custom_edit_code=None):
        """Upload code to rentry.co and return the URL"""
        try:
            # Determine if we're creating new or editing existing
            is_editing = custom_url and not self.check_url_availability(custom_url) and custom_edit_code
            
            # Check if custom URL is already taken
            if custom_url:
                if not self.check_url_availability(custom_url):
                    # URL is taken - check if user provided edit code to update existing paste
                    if not custom_edit_code:
                        return {"error": f"URL '{custom_url}' is already taken. Please choose a different URL or provide the edit code to update it."}
                    # If edit code provided, we'll try to update the existing paste
            
            # Get CSRF token from appropriate page
            if is_editing:
                csrf_token = self.get_csrf_token(f"{self.base_url}/{custom_url}/edit")
            else:
                csrf_token = self.get_csrf_token()
            
            if not csrf_token:
                return {"error": "Failed to get CSRF token"}
            
            # Prepare data for upload
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'text': code_text
            }
            
            if is_editing:
                # For editing existing paste - use the /edit endpoint
                data['edit_code'] = custom_edit_code
                target_url = f"{self.base_url}/{custom_url}/edit"
                headers = {
                    'Referer': target_url,
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            else:
                # For creating new paste
                if custom_url:
                    data['url'] = custom_url
                if custom_edit_code:
                    data['edit_code'] = custom_edit_code
                target_url = self.base_url
                headers = {
                    'Referer': self.base_url,
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            
            # Make POST request
            response = self.session.post(target_url, data=data, headers=headers, allow_redirects=True)
            
            # Check for success
            if is_editing:
                # For editing, check the response
                expected_view_url = f"{self.base_url}/{custom_url}"
                expected_edit_url = f"{self.base_url}/{custom_url}/edit"
                content = response.text
                
                # Check for edit failure indicators
                if ('invalid edit code' in content.lower() or 
                    'wrong edit code' in content.lower() or 
                    'incorrect edit code' in content.lower() or
                    'edit code is required' in content.lower() or
                    'text-danger' in content):
                    return {"error": "Edit failed - invalid edit code"}
                
                # Success if redirected to view page or still on edit page without errors
                if (response.url == expected_view_url or 
                    (response.url == expected_edit_url and 'text-danger' not in content)):
                    return {
                        "success": True,
                        "url": expected_view_url,
                        "edit_code": custom_edit_code,
                        "message": "Code updated successfully!"
                    }
            else:
                # For creation, check if we got redirected to a new page
                if response.url != self.base_url and not response.url.endswith('/'):
                    result = {
                        "success": True,
                        "url": response.url,
                        "message": "Code uploaded successfully!"
                    }
                    if custom_edit_code:
                        result["edit_code"] = custom_edit_code
                    return result
            
            # Check response content for success indicators
            content = response.text
            
            # Look for URL in the response content
            url_patterns = [
                r'https://rentry\.co/([a-zA-Z0-9_-]+)',
                r'rentry\.co/([a-zA-Z0-9_-]+)',
                r'href=["\']/?([a-zA-Z0-9_-]{6,})["\']',
            ]
            
            for pattern in url_patterns:
                url_match = re.search(pattern, content)
                if url_match:
                    extracted = url_match.group(1)
                    # Skip common page names
                    if extracted not in ['new', 'edit', 'raw', 'api', 'about', 'contact']:
                        if extracted.startswith('http'):
                            full_url = extracted
                        else:
                            full_url = f"{self.base_url}/{extracted}"
                        
                        result = {
                            "success": True,
                            "url": full_url,
                            "message": "Code uploaded successfully!"
                        }
                        if custom_edit_code:
                            result["edit_code"] = custom_edit_code
                        return result
            
            # If we get here, upload/edit likely failed
            if 'error' in content.lower() or 'invalid' in content.lower():
                if is_editing:
                    return {"error": "Edit failed - invalid edit code or other error"}
                else:
                    return {"error": "Upload failed - invalid input or URL already exists"}
            
            if is_editing:
                return {"error": "Edit completed but could not confirm success. Please check the URL manually."}
            else:
                return {"error": "Upload completed but could not extract URL. The paste may have been created successfully - please check rentry.co manually."}
                
        except requests.exceptions.RequestException as e:
            return {"error": f"Network error: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    def auto_wrap_code(self, code_text):
        """Automatically wrap code with markdown code blocks if not already wrapped"""
        code_text = code_text.strip()
        
        # Check if code is already wrapped with triple backticks
        if code_text.startswith('```') and code_text.endswith('```'):
            return code_text
        
        # Check if it's already wrapped with single backticks (convert to triple)
        if code_text.startswith('`') and code_text.endswith('`') and not code_text.startswith('```'):
            # Remove single backticks and wrap with triple backticks
            code_text = code_text[1:-1].strip()
        
        # Try to detect language based on common patterns
        language = self.detect_language(code_text)
        
        # Wrap with triple backticks
        if language:
            return f"```{language}\n{code_text}\n```"
        else:
            return f"```\n{code_text}\n```"
    
    def detect_language(self, code_text):
        """Simple language detection based on common patterns"""
        lines = code_text.split('\n')
        first_lines = '\n'.join(lines[:5]).lower()  # Check first 5 lines
        
        # Common patterns for different languages
        patterns = {
            'python': [
                r'import\s+\w+', r'from\s+\w+\s+import', r'def\s+\w+\s*\(', r'class\s+\w+\s*\(', 
                r'if\s+__name__\s*==\s*["\']__main__["\']', r'print\s*\(', r'#!/usr/bin/env python'
            ],
            'javascript': [
                r'function\s+\w+\s*\(', r'const\s+\w+\s*=', r'let\s+\w+\s*=', r'var\s+\w+\s*=',
                r'console\.log\s*\(', r'require\s*\(', r'=>', r'import\s+.*from'
            ],
            'java': [
                r'public\s+class\s+\w+', r'public\s+static\s+void\s+main', r'System\.out\.print',
                r'import\s+java\.', r'package\s+\w+'
            ],
            'cpp': [
                r'#include\s*<.*>', r'int\s+main\s*\(', r'std::', r'cout\s*<<', r'cin\s*>>',
                r'using\s+namespace\s+std', r'#include\s*".*"', r'class\s+\w+\s*{',
                r'public\s*:', r'private\s*:', r'protected\s*:', r'template\s*<.*>',
                r'vector\s*<.*>', r'string\s+\w+', r'endl\s*;'
            ],
            'c': [
                r'#include\s*<.*>', r'int\s+main\s*\(', r'printf\s*\(', r'scanf\s*\('
            ],
            'html': [
                r'<html', r'<body', r'<div', r'<p>', r'<!doctype', r'<script', r'<style'
            ],
            'css': [
                r'[.#][\w-]+\s*{', r'@media', r'background-color:', r'font-family:', r'margin:', r'padding:'
            ],
            'sql': [
                r'select\s+.*from', r'insert\s+into', r'update\s+.*set', r'delete\s+from',
                r'create\s+table', r'alter\s+table'
            ],
            'json': [
                r'^\s*[{[]', r'["\'][\w-]+["\']:\s*[{[\]"\'0-9]'
            ],
            'yaml': [
                r'^\s*[\w-]+:\s*$', r'^\s*-\s+\w+', r'version:', r'apiVersion:'
            ],
            'bash': [
                r'#!/bin/bash', r'#!/bin/sh', r'echo\s+["\']', r'if\s*\[.*\]', r'for\s+\w+\s+in'
            ],
            'go': [
                r'package\s+main', r'import\s+\(', r'func\s+\w+\s*\(', r'fmt\.Print', r'go\s+\w+'
            ],
            'rust': [
                r'fn\s+main\s*\(', r'let\s+\w+\s*=', r'println!\s*\(', r'use\s+std::', r'cargo'
            ],
            'php': [
                r'<\?php', r'\$\w+\s*=', r'echo\s+', r'function\s+\w+\s*\(', r'class\s+\w+\s*{'
            ]
        }
        
        # Check patterns for each language
        for lang, lang_patterns in patterns.items():
            for pattern in lang_patterns:
                if re.search(pattern, first_lines):
                    return lang
        
        return None  # No language detected

    def format_code(self, code_text, language=None):
        """Format code based on detected or specified language"""
        try:
            # Ensure code_text is a string
            if not isinstance(code_text, str):
                return str(code_text) if code_text else ""
            
            # If no language specified, try to detect it
            if not language:
                language = self.detect_language(code_text)
            
            # Apply appropriate formatting based on language
            formatted_code = None
            if language == 'python':
                formatted_code = self.format_python(code_text)
            elif language == 'javascript':
                formatted_code = self.format_javascript(code_text)
            elif language == 'json':
                formatted_code = self.format_json(code_text)
            elif language == 'html':
                formatted_code = self.format_html(code_text)
            elif language == 'css':
                formatted_code = self.format_css(code_text)
            elif language == 'sql':
                formatted_code = self.format_sql(code_text)
            elif language == 'cpp' or language == 'c':
                formatted_code = self.format_cpp(code_text)
            else:
                # For other languages, just clean up basic formatting
                formatted_code = self.format_generic(code_text)
            
            # Ensure we return a valid string
            return formatted_code if formatted_code is not None else code_text
                
        except Exception as e:
            # If formatting fails, return original code
            return code_text
    
    def format_python(self, code_text):
        """Format Python code using autopep8"""
        try:
            # Remove any existing markdown wrapping
            clean_code = self.remove_markdown_wrapper(code_text)
            formatted = autopep8.fix_code(clean_code, options={
                'aggressive': 1,
                'max_line_length': 88
            })
            return formatted.strip()
        except Exception:
            return code_text
    
    def format_javascript(self, code_text):
        """Format JavaScript code using jsbeautifier"""
        try:
            # Remove any existing markdown wrapping
            clean_code = self.remove_markdown_wrapper(code_text)
            formatted = jsbeautifier.beautify(clean_code)
            return formatted.strip()
        except Exception:
            return code_text
    
    def format_json(self, code_text):
        """Format JSON code"""
        try:
            # Remove any existing markdown wrapping
            clean_code = self.remove_markdown_wrapper(code_text)
            # Try to parse and reformat JSON
            parsed = json.loads(clean_code)
            formatted = json.dumps(parsed, indent=2, sort_keys=True)
            return formatted
        except Exception:
            return code_text
    
    def format_html(self, code_text):
        """Format HTML code using BeautifulSoup"""
        try:
            # Remove any existing markdown wrapping
            clean_code = self.remove_markdown_wrapper(code_text)
            soup = BeautifulSoup(clean_code, 'html.parser')
            formatted = soup.prettify()
            return formatted.strip()
        except Exception:
            return code_text
    
    def format_css(self, code_text):
        """Format CSS code"""
        try:
            # Remove any existing markdown wrapping
            clean_code = self.remove_markdown_wrapper(code_text)
            # Basic CSS formatting
            formatted = self.format_css_basic(clean_code)
            return formatted.strip()
        except Exception:
            return code_text
    
    def format_css_basic(self, css_code):
        """Basic CSS formatting"""
        # Remove extra whitespace and add proper indentation
        lines = css_code.strip().split('\n')
        formatted_lines = []
        indent_level = 0
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Decrease indent for closing braces
            if line.startswith('}'):
                indent_level = max(0, indent_level - 1)
            
            # Add proper indentation
            formatted_lines.append('  ' * indent_level + line)
            
            # Increase indent for opening braces
            if line.endswith('{'):
                indent_level += 1
        
        return '\n'.join(formatted_lines)
    
    def format_sql(self, code_text):
        """Format SQL code with basic formatting"""
        try:
            # Remove any existing markdown wrapping
            clean_code = self.remove_markdown_wrapper(code_text)
            # Basic SQL formatting
            formatted = self.format_sql_basic(clean_code)
            return formatted.strip()
        except Exception:
            return code_text
    
    def format_sql_basic(self, sql_code):
        """Basic SQL formatting"""
        # Keywords to uppercase
        keywords = ['SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'JOIN', 'INNER', 'LEFT', 'RIGHT',
                   'ON', 'GROUP BY', 'ORDER BY', 'HAVING', 'UNION', 'CREATE', 'ALTER', 'DROP', 'TABLE',
                   'INDEX', 'VIEW', 'AND', 'OR', 'NOT', 'IN', 'LIKE', 'BETWEEN', 'IS', 'NULL', 'AS']
        
        formatted = sql_code
        for keyword in keywords:
            # Replace with proper case
            formatted = re.sub(r'\b' + keyword.lower() + r'\b', keyword, formatted, flags=re.IGNORECASE)
        
        return formatted
    
    def format_generic(self, code_text):
        """Generic formatting for unknown languages"""
        # Remove any existing markdown wrapping
        clean_code = self.remove_markdown_wrapper(code_text)
        
        # Basic cleanup - remove extra whitespace, normalize line endings
        lines = clean_code.split('\n')
        formatted_lines = []
        
        for line in lines:
            # Remove trailing whitespace but preserve leading whitespace (indentation)
            formatted_line = line.rstrip()
            if formatted_line or not formatted_lines or formatted_lines[-1]:  # Keep non-empty lines and single empty lines
                formatted_lines.append(formatted_line)
        
        # Remove trailing empty lines
        while formatted_lines and not formatted_lines[-1]:
            formatted_lines.pop()
        
        return '\n'.join(formatted_lines)
    
    def remove_markdown_wrapper(self, code_text):
        """Remove markdown code block wrappers"""
        # Ensure we have a string
        if not isinstance(code_text, str):
            return str(code_text) if code_text else ""
        
        code_text = code_text.strip()
        
        # Remove triple backticks with optional language
        if code_text.startswith('```'):
            lines = code_text.split('\n')
            if len(lines) > 1:
                # Remove first line (```language)
                lines = lines[1:]
                # Remove last line if it's just ```
                if lines and lines[-1].strip() == '```':
                    lines = lines[:-1]
                code_text = '\n'.join(lines)
        
        # Remove single backticks
        if code_text.startswith('`') and code_text.endswith('`'):
            code_text = code_text[1:-1]
        
        return code_text



    def format_cpp(self, code_text):
        """Format C++ code with basic formatting"""
        try:
            # Remove any existing markdown wrapping
            clean_code = self.remove_markdown_wrapper(code_text)
            # Basic C++ formatting
            formatted = self.format_cpp_basic(clean_code)
            return formatted.strip()
        except Exception:
            return code_text
    
    def format_cpp_basic(self, cpp_code):
        """Basic C++ formatting"""
        lines = cpp_code.strip().split('\n')
        formatted_lines = []
        indent_level = 0
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Handle special cases
            original_line = line
            
            # Decrease indent for closing braces
            if line.startswith('}'):
                indent_level = max(0, indent_level - 1)
            
            # Add proper indentation
            formatted_line = '    ' * indent_level + line
            
            # Fix common formatting issues
            # Add space after keywords
            formatted_line = re.sub(r'\b(if|while|for|switch)\s*\(', r'\1 (', formatted_line)
            
            # Add space around operators
            formatted_line = re.sub(r'(\w)\s*([+\-*/%=<>!]+)\s*(\w)', r'\1 \2 \3', formatted_line)
            
            # Fix cin/cout spacing
            formatted_line = re.sub(r'cin\s*>>\s*', 'cin >> ', formatted_line)
            formatted_line = re.sub(r'cout\s*<<\s*', 'cout << ', formatted_line)
            
            # Fix semicolon spacing
            formatted_line = re.sub(r';\s*([a-zA-Z])', r'; \1', formatted_line)
            
            # Add space after commas
            formatted_line = re.sub(r',\s*([a-zA-Z])', r', \1', formatted_line)
            
            formatted_lines.append(formatted_line)
            
            # Increase indent for opening braces
            if line.endswith('{'):
                indent_level += 1
        
        return '\n'.join(formatted_lines)

# Initialize uploader
uploader = RentryUploader()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    try:
        data = request.get_json()
        
        if not data or 'code' not in data:
            return jsonify({"error": "No code provided"}), 400
        
        code_text = data['code'].strip()
        if not code_text:
            return jsonify({"error": "Code cannot be empty"}), 400
        
        # Extract clean URL slug from user input (handles full URLs)
        raw_url = data.get('url', '').strip()
        custom_url = uploader.extract_url_slug(raw_url) if raw_url else None
        custom_edit_code = data.get('edit_code', '').strip() or None
        
        # Auto wrap code
        code_text = uploader.auto_wrap_code(code_text)
        
        # Upload to rentry.co
        result = uploader.upload_code(code_text, custom_url, custom_edit_code)
        
        if result.get('success'):
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/format', methods=['POST'])
def format_code():
    try:
        data = request.get_json()
        
        if not data or 'code' not in data:
            return jsonify({"error": "No code provided"}), 400
        
        code_text = data['code'].strip()
        if not code_text:
            return jsonify({"error": "Code cannot be empty"}), 400
        
        # Get optional language hint
        language = data.get('language') or ''
        if isinstance(language, str):
            language = language.strip() or None
        else:
            language = None
        
        # Format the code
        formatted_code = uploader.format_code(code_text, language)
        
        return jsonify({
            "success": True,
            "formatted_code": formatted_code,
            "message": "Code formatted successfully!"
        })
        
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001) 