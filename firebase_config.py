import os
import firebase_admin
from firebase_admin import credentials, firestore

def initialize_firebase():
    if not firebase_admin._apps:
        try:
            # Try to use the JSON file first (standard Firebase approach)
            json_path = "../../../Downloads/barman-store-6e6c6-firebase-adminsdk-fbsvc-b4ebdbb71f.json"
            if os.path.exists(json_path):
                cred = credentials.Certificate(json_path)
                firebase_admin.initialize_app(cred)
                return True

            # Fallback to environment variables
            project_id = os.getenv("FIREBASE_PROJECT_ID")
            private_key_id = os.getenv("FIREBASE_PRIVATE_KEY_ID")
            private_key = os.getenv("FIREBASE_PRIVATE_KEY")
            client_email = os.getenv("FIREBASE_CLIENT_EMAIL")
            client_id = os.getenv("FIREBASE_CLIENT_ID")
            client_x509_cert_url = os.getenv("FIREBASE_CLIENT_X509_CERT_URL")

            if not all([project_id, private_key_id, private_key, client_email, client_id, client_x509_cert_url]):
                return False

            # Process the private key - it should already be properly formatted from .env
            processed_key = private_key.replace('\\n', '\n')

            cred = credentials.Certificate({
                "type": "service_account",
                "project_id": project_id,
                "private_key_id": private_key_id,
                "private_key": processed_key,
                "client_email": client_email,
                "client_id": client_id,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": client_x509_cert_url
            })
            firebase_admin.initialize_app(cred)
            return True
        except Exception as e:
            print(f"Firebase initialization failed: {e}")
            return False

# Initialize Firestore client if Firebase is initialized
firebase_initialized = initialize_firebase()
db = firestore.client() if firebase_initialized else None