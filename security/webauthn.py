import base64
import json
import os
import datetime
from typing import Dict, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI
from config.mybank_db import Users
from security.audit import log_operation

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


class WebAuthnManager:
    """WebAuthn authentication manager"""

    def __init__(self, rp_id: str, rp_name: str):
        """
        Initialize WebAuthn manager

        Parameters:
        - rp_id: Relying Party ID (usually the domain name)
        - rp_name: Relying Party name
        """
        self.rp_id = rp_id
        self.rp_name = rp_name

    def generate_registration_options(self, user_id: str, username: str) -> Dict[str, Any]:
        """
        Generate registration options

        Parameters:
        - user_id: User ID
        - username: Username

        Returns:
        - Registration options JSON
        """
        # Generate random challenge
        challenge = os.urandom(32)
        challenge_b64 = base64.b64encode(challenge).decode('ascii')

        # Simulate registration options
        options = {
            'challenge': challenge_b64,
            'rp': {
                'name': self.rp_name,
                'id': self.rp_id
            },
            'user': {
                'id': user_id,
                'name': username,
                'displayName': username
            },
            'pubKeyCredParams': [
                {'type': 'public-key', 'alg': -7},  # ES256
                {'type': 'public-key', 'alg': -257}  # RS256
            ],
            'timeout': 60000,
            'attestation': 'direct',
            'authenticatorSelection': {
                'authenticatorAttachment': 'platform',
                'requireResidentKey': False,
                'userVerification': 'preferred'
            }
        }

        # Store challenge for subsequent verification
        session = Session()
        try:
            user = session.query(Users).filter_by(user_id=user_id).first()
            if user:
                if not hasattr(user, 'webauthn_data'):
                    # Ensure the database has this field
                    pass
                else:
                    # Store challenge
                    webauthn_data = json.loads(user.webauthn_data) if user.webauthn_data else {}
                    webauthn_data['registration_challenge'] = challenge_b64
                    webauthn_data['registration_challenge_time'] = datetime.datetime.now(
                        tz=datetime.timezone.utc).isoformat()
                    user.webauthn_data = json.dumps(webauthn_data)
                    session.commit()
        finally:
            session.close()

        return options

    def verify_registration(self, user_id: str, credential: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify registration response

        Parameters:
        - user_id: User ID
        - credential: Credential data

        Returns:
        - Verification result
        """
        session = Session()
        try:
            user = session.query(Users).filter_by(user_id=user_id).first()
            if not user:
                raise ValueError("User not found")

            # Extract stored challenge
            webauthn_data = json.loads(user.webauthn_data) if user.webauthn_data else {}
            stored_challenge = webauthn_data.get('registration_challenge')

            if not stored_challenge:
                raise ValueError("No registration challenge found")

            # Verify if challenge matches
            client_challenge = credential.get('response', {}).get('clientDataJSON', {}).get('challenge')
            if client_challenge != stored_challenge:
                raise ValueError("Challenge mismatch")

            # Extract credential ID and public key
            credential_id = credential.get('id')
            public_key = credential.get('response', {}).get('attestationObject', {}).get('authData', {}).get(
                'attestedCredentialData', {}).get('credentialPublicKey')

            # Store credential
            credentials = webauthn_data.get('credentials', [])
            credentials.append({
                'id': credential_id,
                'publicKey': public_key,
                'type': 'public-key',
                'registeredAt': datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
            })

            webauthn_data['credentials'] = credentials
            webauthn_data.pop('registration_challenge', None)  # Remove challenge
            webauthn_data.pop('registration_challenge_time', None)

            user.webauthn_data = json.dumps(webauthn_data)
            session.commit()

            # Record operation
            log_operation(
                user_id,
                "webauthn_register",
                "Registered new WebAuthn credential"
            )

            return {
                'success': True,
                'credential_id': credential_id
            }
        finally:
            session.close()

    def generate_authentication_options(self, username: str) -> Dict[str, Any]:
        """
        Generate authentication options

        Parameters:
        - username: Username

        Returns:
        - Authentication options JSON
        """
        session = Session()
        try:
            user = session.query(Users).filter_by(email=username).first()
            if not user:
                raise ValueError("User not found")

            # Extract stored credentials
            webauthn_data = json.loads(user.webauthn_data) if user.webauthn_data else {}
            credentials = webauthn_data.get('credentials', [])

            if not credentials:
                raise ValueError("No credentials found")

            # Generate random challenge
            challenge = os.urandom(32)
            challenge_b64 = base64.b64encode(challenge).decode('ascii')

            # In actual implementation, this would call the FIDO2 library
            # options = self.server.authenticate_begin(credentials)

            # Simulate authentication options
            options = {
                'challenge': challenge_b64,
                'timeout': 60000,
                'rpId': self.rp_id,
                'allowCredentials': [
                    {
                        'type': 'public-key',
                        'id': cred['id']
                    } for cred in credentials
                ],
                'userVerification': 'preferred'
            }

            # Store challenge for subsequent verification
            webauthn_data['authentication_challenge'] = challenge_b64
            webauthn_data['authentication_challenge_time'] = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
            user.webauthn_data = json.dumps(webauthn_data)
            session.commit()

            return options
        finally:
            session.close()

    def verify_authentication(self, username: str, credential: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify authentication response

        Parameters:
        - username: Username
        - credential: Credential data

        Returns:
        - Verification result
        """
        session = Session()
        try:
            user = session.query(Users).filter_by(email=username).first()
            if not user:
                raise ValueError("User not found")

            # Extract stored challenge and credentials
            webauthn_data = json.loads(user.webauthn_data) if user.webauthn_data else {}
            stored_challenge = webauthn_data.get('authentication_challenge')

            if not stored_challenge:
                raise ValueError("No authentication challenge found")

            # Verify if challenge matches
            client_challenge = credential.get('response', {}).get('clientDataJSON', {}).get('challenge')
            if client_challenge != stored_challenge:
                raise ValueError("Challenge mismatch")

            # In actual implementation, this would call the FIDO2 library for complete verification
            # result = self.server.authenticate_complete(
            #    session['authentication_state'],
            #    credentials,
            #    credential.get('clientData'),
            #    credential.get('authenticatorData'),
            #    credential.get('signature')
            # )

            # Simulate successful verification
            # In actual implementation, complete signature verification should be performed here

            # Clear challenge
            webauthn_data.pop('authentication_challenge', None)
            webauthn_data.pop('authentication_challenge_time', None)
            user.webauthn_data = json.dumps(webauthn_data)
            session.commit()

            # Record operation
            log_operation(
                user.user_id,
                "webauthn_authenticate",
                "Authenticated with WebAuthn"
            )

            return {
                'success': True,
                'user_id': user.user_id
            }
        finally:
            session.close()


# Create WebAuthn manager instance
webauthn_manager = WebAuthnManager('bankingsystem.example.com', 'MyBank')


def register_webauthn_credential(user_id: str, username: str) -> Dict[str, Any]:
    """Register WebAuthn credentials"""
    return webauthn_manager.generate_registration_options(user_id, username)


def verify_webauthn_registration(user_id: str, credential: Dict[str, Any]) -> Dict[str, Any]:
    """Verify WebAuthn registration"""
    return webauthn_manager.verify_registration(user_id, credential)


def authenticate_with_webauthn(username: str) -> Dict[str, Any]:
    """Use WebAuthn for authentication"""
    return webauthn_manager.generate_authentication_options(username)


def verify_webauthn_authentication(username: str, credential: Dict[str, Any]) -> Dict[str, Any]:
    """Verify WebAuthn authentication"""
    return webauthn_manager.verify_authentication(username, credential)