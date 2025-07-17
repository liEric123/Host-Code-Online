# User Accounts Setup Guide

Your Host Code Online app now has an optional accounts system! Users can continue using the app without logging in, or they can create accounts to track their uploads.

## Quick Start

1. **Install new dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the app:**
   ```bash
   python app.py
   ```
   The database will be automatically created on first run.

## New Features

### For Anonymous Users (No Change)
- Everything works exactly as before
- No login required
- Upload code and get rentry.co links instantly

### For Registered Users
- **Create Account**: Visit `/register` to sign up
- **Sign In**: Visit `/login` to access your account
- **Dashboard**: View all your uploaded code at `/dashboard`
- **Track Uploads**: All uploads are automatically saved to your account
- **Manage History**: View, access, and remove uploads from your account

## User Interface Changes

### Navigation
- **Anonymous users** see: Sign In | Register
- **Logged-in users** see: 👤 Username | Dashboard | Logout

### Upload Pages
- **New checkbox** for logged-in users: "Save to my account" (checked by default)
- Users can opt-out of saving specific uploads if they want them to remain anonymous

### Dashboard Features
- **Upload History**: Table showing all your uploads
- **Quick Access**: Direct links to all your rentry.co pastes
- **Upload Info**: Title, preview, language, date, and edit code status
- **Remove Option**: Remove uploads from your account (doesn't delete from rentry.co)
- **Quick Actions**: Easy access to create new uploads

## Database Structure

The app uses SQLite by default (`app.db` file) with two tables:

### Users Table
- Username (unique)
- Email (unique, used for login)
- Password (hashed with werkzeug)
- Created date

### Uploads Table
- Title (from custom URL or auto-generated)
- Rentry.co URL
- Code preview (first 200 characters)
- Programming language (auto-detected)
- Has edit code (boolean, for security)
- Created/updated dates

## Security Features

- **Password Hashing**: Uses werkzeug security for password hashing
- **Edit Code Privacy**: Edit codes are not stored in the database for security
- **Session Management**: Flask-Login handles secure session management
- **Optional Accounts**: Anonymous usage remains fully functional

## Configuration

### Environment Variables (Optional)
- `SECRET_KEY`: Set in production (defaults to dev key)
- `DATABASE_URL`: For production databases (defaults to SQLite)

### Database Migration
To use PostgreSQL or MySQL in production, just change the `DATABASE_URL` environment variable.

## How It Works

1. **Anonymous Upload**: Works exactly as before, nothing is saved
2. **Logged-in Upload**: 
   - Upload happens normally to rentry.co
   - If successful and "Save to my account" is checked
   - Upload info is saved to user's account
   - User can view it later in dashboard

## Benefits

- **No Disruption**: Existing workflow unchanged
- **Optional Enhancement**: Users choose if they want accounts
- **Upload Tracking**: Never lose track of your code uploads
- **Easy Management**: Centralized dashboard for all uploads
- **Security Focused**: Edit codes not stored, passwords hashed

## Next Steps

Your users can now:
1. Continue using the app anonymously as before
2. Create accounts to track their uploads
3. Use the dashboard to manage their upload history
4. Switch between anonymous and tracked uploads as needed

The app maintains full backward compatibility while adding the account management features you requested! 