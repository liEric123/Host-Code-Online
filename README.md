# Host Code Online

A simple web application that allows you to upload code to rentry.co and get a shareable URL instantly.

## Features

- 🚀 **Easy Upload**: Paste your code and get a rentry.co URL immediately
- 🎨 **Beautiful UI**: Modern, responsive web interface
- 🔧 **Custom Options**: Set custom URLs and edit codes
- 📱 **Mobile Friendly**: Works great on all devices
- 🔗 **Instant Sharing**: Copy URLs with one click

## How It Works

This tool uses rentry.co's API to upload your code and return a shareable URL. Rentry.co is a markdown-powered paste service that's perfect for sharing code snippets.

## Installation

1. Clone this repository or download the files
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Start the Flask application:
   ```bash
   python app.py
   ```

2. Open your browser and go to `http://localhost:5001`

3. Paste your code in the text area

4. Optionally set a custom URL and edit code

5. Click "Upload Code" to get your rentry.co URL

## API Endpoints

- `GET /` - Main web interface
- `POST /upload` - Upload code to rentry.co
  
### Upload Request Format
```json
{
    "code": "your code here",
    "url": "optional-custom-url",
    "edit_code": "optional-edit-password"
}
```

### Upload Response Format
```json
{
    "success": true,
    "url": "https://rentry.co/your-url",
    "edit_code": "your-edit-code",
    "message": "Code uploaded successfully!"
}
```

## Features Explained

- **Custom URL**: Choose your own URL path (e.g., rentry.co/my-code)
- **Edit Code**: Set a password to edit your code later
- **Syntax Highlighting**: Rentry.co automatically detects and highlights your code
- **Markdown Support**: Your code is formatted as markdown for better readability

## Tech Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **API**: Rentry.co REST API

## License

MIT License - Feel free to use and modify as needed. 