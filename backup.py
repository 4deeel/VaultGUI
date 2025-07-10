from __future__ import print_function
import os
import sys
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import pickle

# Scopes for Google Drive API
SCOPES = ['https://www.googleapis.com/auth/drive.file']

def authenticate():
    creds = None
    # Load existing credentials if available
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    # If no valid credentials, authenticate
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save credentials for next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    
    return build('drive', 'v3', credentials=creds)

def upload_file(service, file_path, folder_id=None):
    file_name = os.path.basename(file_path)
    file_metadata = {'name': file_name}
    if folder_id:
        file_metadata['parents'] = [folder_id]
    
    media = MediaFileUpload(file_path)
    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id'
    ).execute()
    print(f"Uploaded {file_name} with ID: {file.get('id')}")

def main():
    if len(sys.argv) < 2:
        print("Error: Please provide at least one file to upload.")
        sys.exit(1)
    
    # Authenticate and create Drive API service
    service = authenticate()
    
    # Optional: Create or use a specific folder (you can set folder_id manually)
    folder_id = None  # Replace with your Google Drive folder ID if desired
    
    # Upload each file provided as argument
    for file_path in sys.argv[1:]:
        if os.path.exists(file_path):
            upload_file(service, file_path, folder_id)
        else:
            print(f"Error: File {file_path} does not exist.")
            sys.exit(1)

if __name__ == '__main__':
    main()