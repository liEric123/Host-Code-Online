# Host Code Online

Fast, clean web app for sharing code snippets via rentry.co. No registration required.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features

- **Single Paste**: Quick code sharing with file upload support
- **Multi-File Upload**: Advanced file management with preview system
- **Smart Upload Modes**: Combine files or create separate pastes
- **Code Formatting**: Auto-format code before uploading
- **Security Options**: Write-once pastes or custom edit codes
- **Dark/Light Mode**: Built-in theme toggle
- **Mobile Friendly**: Responsive design for all devices

## Quick Start

```bash
git clone https://github.com/liEric123/Host-Code-Online.git
cd Host-Code-Online
pip install -r requirements.txt
python3 app.py
```

Open: `http://localhost:8000`

## How to Use

**Landing Page** → Choose your upload method:
- **Single Paste**: Perfect for quick snippets or single files
- **Multi-File Upload**: Advanced features for complex projects

**Single Paste** (`/paste`):
- Type/paste code or upload a file
- Optional custom URL and edit code
- Format and upload

**Multi-File Upload** (`/files`):
- Upload multiple files via button or drag & drop
- Preview and select files to upload
- Choose: combine into one paste or create separate pastes
- Set edit codes individually or use same for all

## Supported File Types

Code files: `.py` `.js` `.ts` `.html` `.css` `.json` `.cpp` `.java` `.php` `.rb` `.go` `.rs` `.md` `.sql` `.yml` and more.


## License

MIT License - see [LICENSE](LICENSE) file.

---

**Star this repo if it's helpful!** 
