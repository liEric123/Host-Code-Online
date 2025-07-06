# 🚀 Host Code Online

A fast, elegant web application for hosting and sharing code snippets online using rentry.co. No login required!

![Host Code Online](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

- **🎯 Zero Setup**: No registration or login required
- **📁 File Upload**: Upload code files directly from your computer
- **🎨 Drag & Drop**: Simply drag files onto the interface
- **📱 Mobile Friendly**: Responsive design that works on all devices
- **🌙 Dark Mode**: Built-in light/dark theme toggle
- **✨ Code Formatting**: Automatic code formatting for popular languages
- **🔗 Custom URLs**: Create memorable URLs for your code snippets
- **🔐 Edit Codes**: Set passwords to edit your snippets later
- **🎨 Syntax Support**: Supports 25+ programming languages and file types

## 🔧 Supported File Types

- **Languages**: Python, JavaScript, TypeScript, HTML, CSS, JSON, C++, C, Java, C#, PHP, Ruby, Go, Rust, Swift, Kotlin, Scala
- **Config Files**: YAML, TOML, INI, XML
- **Scripts**: Shell, Batch, PowerShell
- **Documentation**: Markdown, Text files
- **Database**: SQL

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- pip (Python package installer)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/Host-Code-Online.git
   cd Host-Code-Online
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python3 app.py
   ```

4. **Open your browser**
   ```
   http://localhost:5001
   ```

That's it! 🎉

## 🎮 How to Use

### Method 1: Manual Input
1. Paste your code into the textarea
2. Optionally set a custom URL and edit code
3. Click "Upload Code"

### Method 2: File Upload
1. Click "📁 Choose File(s)" button
2. Select one or multiple code files
3. Click "Upload Code"

### Method 3: Drag & Drop
1. Drag your code files onto the textarea
2. Drop them and they'll be automatically loaded
3. Click "Upload Code"

## 🛠️ Technical Details

### Architecture
- **Backend**: Flask (Python)
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **API Integration**: rentry.co API for hosting
- **Styling**: Custom CSS with CSS Variables for theming

### Key Components

- **`app.py`**: Main Flask application with routing and rentry.co integration
- **`templates/index.html`**: Single-page frontend with all functionality
- **`requirements.txt`**: Python dependencies
- **File Processing**: Client-side JavaScript for file handling
- **Code Formatting**: Built-in formatters for multiple languages

### Features Deep Dive

#### File Upload & Drag-and-Drop
- **Size Limit**: 1MB per file
- **Multiple Files**: Automatically combines with headers
- **Content Handling**: Smart replace/append logic
- **Error Handling**: Graceful validation and user feedback

#### Code Formatting
- **Language Detection**: Automatic language recognition
- **Formatters**: Built-in formatters for Python, JavaScript, JSON, HTML, CSS, SQL, C++
- **Fallback**: Generic formatting for unsupported languages

#### Dark Mode
- **CSS Variables**: Seamless theme switching
- **Persistence**: Theme choice saved in localStorage
- **Animations**: Smooth transitions between themes

## 📋 API Reference

### Upload Endpoint
```
POST /upload
Content-Type: application/json

{
  "code": "your code here",
  "url": "custom-url (optional)",
  "edit_code": "edit-password (optional)"
}
```

### Format Endpoint
```
POST /format
Content-Type: application/json

{
  "code": "your code here",
  "language": "python (optional)"
}
```

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Test thoroughly**
5. **Commit your changes**
   ```bash
   git commit -m "Add amazing feature"
   ```
6. **Push to your branch**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

### Development Setup

1. **Clone your fork**
   ```bash
   git clone https://github.com/yourusername/Host-Code-Online.git
   ```

2. **Create a virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run in development mode**
   ```bash
   python3 app.py
   ```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [rentry.co](https://rentry.co) for providing the hosting service
- [Flask](https://flask.palletsprojects.com/) for the web framework
- All contributors who help improve this project

## 📊 Project Stats

- **Languages**: Python, JavaScript, HTML, CSS
- **Dependencies**: Flask, Requests, BeautifulSoup4, autopep8, jsbeautifier
- **File Size**: ~30KB total
- **Performance**: Handles files up to 1MB, supports 25+ languages

## 🔗 Links

- **Live Demo**: [Coming Soon]
- **Issues**: [Report bugs or request features](https://github.com/yourusername/Host-Code-Online/issues)
- **Discussions**: [Join the conversation](https://github.com/yourusername/Host-Code-Online/discussions)

## 📈 Roadmap

- [ ] Add more language formatters
- [ ] Implement syntax highlighting preview
- [ ] Add batch file processing
- [ ] Create browser extension
- [ ] Add API rate limiting
- [ ] Implement code expiration options
- [ ] Add code sharing via QR codes

---

⭐ **Star this repo if you find it helpful!**

Made with ❤️ by the open source community 