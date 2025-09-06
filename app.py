from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, BooleanField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import re
import random
import string
import json
import autopep8
import jsbeautifier
from bs4 import BeautifulSoup
from datetime import datetime
import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploads = db.relationship('Upload', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rentry_url = db.Column(db.String(200), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    language = db.Column(db.String(50))  # Detected programming language
    has_edit_code = db.Column(db.Boolean, default=False)  # Whether this upload has an edit code
    edit_code = db.Column(db.String(100))  # The actual edit code (only stored if user provided one)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Upload {self.title}>'
    
    @property
    def url_slug(self):
        """Get just the URL slug (last part after slash)"""
        return self.rentry_url.split('/')[-1]

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Please use a different username.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Please use a different email address.')

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
        
        # Try to detect language based on common patterns (no filename available here)
        language = self.detect_language(code_text)
        
        # Wrap with triple backticks
        if language:
            return f"```{language}\n{code_text}\n```"
        else:
            return f"```\n{code_text}\n```"
    
    def detect_language_from_filename(self, filename):
        """Detect language from file extension"""
        if not filename:
            return None
            
        # Get file extension
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        
        # Map extensions to languages
        extension_map = {
            # Python
            'py': 'python',
            'pyw': 'python',
            'pyx': 'python',
            
            # JavaScript/TypeScript
            'js': 'javascript',
            'jsx': 'javascript',
            'ts': 'typescript',
            'tsx': 'typescript',
            'mjs': 'javascript',
            'cjs': 'javascript',
            
            # Java
            'java': 'java',
            'class': 'java',
            
            # C/C++
            'c': 'c',
            'h': 'c',
            'cpp': 'cpp',
            'cxx': 'cpp',
            'cc': 'cpp',
            'hpp': 'cpp',
            'hxx': 'cpp',
            'hh': 'cpp',
            
            # C#
            'cs': 'csharp',
            
            # Web
            'html': 'html',
            'htm': 'html',
            'xhtml': 'html',
            'css': 'css',
            'scss': 'scss',
            'sass': 'sass',
            'less': 'less',
            
            # Data formats
            'json': 'json',
            'xml': 'xml',
            'yaml': 'yaml',
            'yml': 'yaml',
            'toml': 'toml',
            'ini': 'ini',
            'cfg': 'ini',
            'conf': 'ini',
            
            # Shell/Scripts
            'sh': 'bash',
            'bash': 'bash',
            'zsh': 'bash',
            'fish': 'bash',
            'bat': 'batch',
            'cmd': 'batch',
            'ps1': 'powershell',
            
            # Other languages
            'php': 'php',
            'rb': 'ruby',
            'go': 'go',
            'rs': 'rust',
            'swift': 'swift',
            'kt': 'kotlin',
            'scala': 'scala',
            'sql': 'sql',
            'md': 'markdown',
            'txt': 'text',
            
            # Vue/React
            'vue': 'vue',
            
            # R
            'r': 'r',
            
            # Perl
            'pl': 'perl',
            'pm': 'perl',
        }
        
        return extension_map.get(ext, None)

    def detect_language(self, code_text, filename=None):
        """Enhanced language detection: first try filename, then content patterns"""
        
        # First, try to detect from filename if provided
        if filename:
            lang_from_filename = self.detect_language_from_filename(filename)
            if lang_from_filename:
                return lang_from_filename
        
        # If filename detection fails, fall back to content analysis
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

    def format_code(self, code_text, language=None, filename=None):
        """Format code based on detected or specified language"""
        try:
            # Ensure code_text is a string
            if not isinstance(code_text, str):
                return str(code_text) if code_text else ""
            
            # If no language specified, try to detect it
            if not language:
                language = self.detect_language(code_text, filename)
            
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

    def delete_paste(self, url_slug, edit_code):
        """Delete a paste from rentry.co"""
        try:
            if not url_slug or not edit_code:
                return {"error": "URL slug and edit code are required for deletion"}
            
            # First, verify the edit code is valid by trying to access the edit page
            edit_url = f"{self.base_url}/{url_slug}/edit"
            
            # Get CSRF token and check if edit page is accessible
            csrf_token = self.get_csrf_token(edit_url)
            if not csrf_token:
                return {"error": "Failed to access edit page - paste may not exist or edit code is invalid"}
            
            # Try to edit with a test to validate the edit code first
            headers = {
                'Referer': edit_url,
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            
            # First, try to validate edit code by making a small edit
            test_data = {
                'csrfmiddlewaretoken': csrf_token,
                'edit_code': edit_code,
                'text': '[TESTING_EDIT_CODE]'  # Test content to validate edit code
            }
            
            test_response = self.session.post(edit_url, data=test_data, headers=headers, allow_redirects=True)
            
            if test_response.status_code == 200:
                content = test_response.text.lower()
                
                # Check for edit code validation errors
                if ('invalid edit code' in content or 
                    'wrong edit code' in content or 
                    'incorrect edit code' in content or
                    'edit code is required' in content or
                    'text-danger' in content):
                    return {"error": "Invalid edit code - cannot access paste for editing. The saved edit code may have changed or expired. Please check the saved edit code in your dashboard or try entering the current edit code manually."}
                
                # If we reach here, edit code is valid. Now try to delete the content
                # Get a fresh CSRF token for the actual deletion
                csrf_token = self.get_csrf_token(edit_url)
                if not csrf_token:
                    return {"error": "Failed to get CSRF token for deletion"}
                
                # Try to clear/delete the content
                delete_data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'edit_code': edit_code,
                    'text': '[DELETED BY USER]'  # Replace content with deletion marker
                }
                
                delete_response = self.session.post(edit_url, data=delete_data, headers=headers, allow_redirects=True)
                
                if delete_response.status_code == 200:
                    delete_content = delete_response.text.lower()
                    
                    # Check for deletion errors
                    if ('invalid edit code' in delete_content or 
                        'wrong edit code' in delete_content or 
                        'incorrect edit code' in delete_content or
                        'text-danger' in delete_content):
                        return {"error": "Edit code became invalid during deletion process. The edit code may have changed or expired. Please verify the correct edit code and try again."}
                    
                    # Verify the content was actually changed by checking the view page
                    view_url = f"{self.base_url}/{url_slug}"
                    view_response = self.session.get(view_url)
                    
                    if view_response.status_code == 200:
                        view_content = view_response.text
                        if '[DELETED BY USER]' in view_content:
                            return {
                                "success": True,
                                "message": "Paste content successfully deleted from rentry.co",
                                "note": "Content replaced with deletion marker - paste URL still exists but content is removed"
                            }
                        else:
                            return {"error": "Content deletion failed - paste content was not changed"}
                    else:
                        # If we can't verify, assume it worked since edit succeeded
                        return {
                            "success": True,
                            "message": "Paste content likely deleted from rentry.co",
                            "note": "Could not verify deletion but edit operation succeeded"
                        }
                else:
                    return {"error": "Failed to delete content - server error during deletion"}
            else:
                return {"error": "Failed to validate edit code - server error"}
            
        except requests.exceptions.RequestException as e:
            return {"error": f"Network error during deletion: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error during deletion: {str(e)}"}

# Initialize uploader
uploader = RentryUploader()

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/paste')
def paste():
    return render_template('paste.html')

@app.route('/files')
def files():
    return render_template('files.html')

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
            # Save upload to user's account if logged in and save_to_account is not explicitly false
            save_to_account = data.get('save_to_account', True)  # Default to True
            if save_to_account:
                saved_upload = save_upload_for_user(
                    rentry_url=result['url'],
                    code_text=code_text,
                    custom_url=custom_url,
                    has_edit_code=bool(custom_edit_code),
                    edit_code=result.get('edit_code'),
                    filename=data.get('filename')
                )
                if saved_upload:
                    result['saved_to_account'] = True
            
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
        
        # Get optional language hint and filename
        language = data.get('language') or ''
        if isinstance(language, str):
            language = language.strip() or None
        else:
            language = None
        
        filename = data.get('filename')
        
        # Format the code
        formatted_code = uploader.format_code(code_text, language, filename)
        
        return jsonify({
            "success": True,
            "formatted_code": formatted_code,
            "message": "Code formatted successfully!"
        })
        
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# Authentication Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now registered!')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            if not next_page or url_for(next_page) != next_page:
                next_page = url_for('dashboard')
            return redirect(next_page)
        # Enhanced error message with category
        flash('🔒 Login failed! The email or password you entered is incorrect. Please check your credentials and try again.', 'error')
    
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    uploads = Upload.query.filter_by(user_id=current_user.id).order_by(Upload.created_at.desc()).all()
    return render_template('dashboard.html', title='My Uploads', uploads=uploads)

@app.route('/dashboard/delete/<int:upload_id>', methods=['POST'])
@login_required
def delete_upload(upload_id):
    upload = Upload.query.filter_by(id=upload_id, user_id=current_user.id).first_or_404()
    db.session.delete(upload)
    db.session.commit()
    flash('Upload removed from your account.')
    return redirect(url_for('dashboard'))

@app.route('/dashboard/delete-both/<int:upload_id>', methods=['POST'])
@login_required
def delete_upload_and_paste(upload_id):
    upload = Upload.query.filter_by(id=upload_id, user_id=current_user.id).first_or_404()
    
    data = request.get_json()
    edit_code = data.get('edit_code', '').strip() if data else ''
    
    # Use saved edit code if available and user didn't provide one
    if not edit_code and upload.edit_code:
        edit_code = upload.edit_code
    
    if not edit_code:
        return jsonify({'error': 'Edit code is required to delete from rentry.co'}), 400
    
    # Try to delete from rentry.co first
    url_slug = upload.url_slug
    delete_result = uploader.delete_paste(url_slug, edit_code)
    
    if delete_result.get('success'):
        # If deletion from rentry.co succeeded, also remove from account
        db.session.delete(upload)
        db.session.commit()
        
        message = delete_result.get('message', 'Deleted successfully')
        if delete_result.get('note'):
            message += f" ({delete_result['note']})"
            
        return jsonify({
            'success': True,
            'message': f'✅ {message} and removed from your account'
        })
    else:
        # If deletion from rentry.co failed, don't remove from account
        return jsonify({
            'error': f"❌ Failed to delete from rentry.co: {delete_result.get('error', 'Unknown error')}"
        }), 400

@app.route('/dashboard/check-edit-code/<int:upload_id>', methods=['POST'])
@login_required
def check_edit_code(upload_id):
    upload = Upload.query.filter_by(id=upload_id, user_id=current_user.id).first_or_404()
    
    return jsonify({
        'has_saved_edit_code': upload.has_edit_code,
        'edit_code': upload.edit_code if upload.has_edit_code else None
    })

@app.route('/dashboard/edit-title/<int:upload_id>', methods=['POST'])
@login_required
def edit_upload_title(upload_id):
    upload = Upload.query.filter_by(id=upload_id, user_id=current_user.id).first_or_404()
    
    data = request.get_json()
    new_title = data.get('title', '').strip()
    
    if not new_title:
        return jsonify({'error': 'Title cannot be empty.'}), 400
    
    if len(new_title) > 200:
        return jsonify({'error': 'Title too long (max 200 characters).'}), 400
    
    upload.title = new_title
    upload.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True, 'title': new_title})

@app.route('/dashboard/edit-language/<int:upload_id>', methods=['POST'])
@login_required
def edit_upload_language(upload_id):
    upload = Upload.query.filter_by(id=upload_id, user_id=current_user.id).first_or_404()
    
    data = request.get_json()
    new_language = data.get('language', '').strip()
    
    # Allow empty language (will show as "Unknown")
    if new_language and len(new_language) > 50:
        return jsonify({'error': 'Language tag too long (max 50 characters).'}), 400
    
    upload.language = new_language if new_language else None
    upload.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True, 'language': new_language})

# Helper function to save upload for logged-in users
def save_upload_for_user(rentry_url, code_text, custom_url=None, has_edit_code=False, edit_code=None, filename=None):
    if current_user.is_authenticated:
        # Generate title from custom URL or auto-generate
        if custom_url:
            title = custom_url
        else:
            # Extract URL from rentry_url
            title = rentry_url.split('/')[-1]
        
        # Detect language using filename if available
        language = uploader.detect_language(code_text, filename)
        
        upload = Upload(
            user_id=current_user.id,
            rentry_url=rentry_url,
            title=title,
            language=language,
            has_edit_code=has_edit_code,
            edit_code=edit_code
        )
        
        db.session.add(upload)
        db.session.commit()
        return upload
    return None

# Database initialization
def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_tables()
    app.run(debug=True, host='0.0.0.0', port=8000) 