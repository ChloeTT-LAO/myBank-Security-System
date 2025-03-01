import base64
import json
import os
import datetime
from typing import Dict, Any, Optional, List, Tuple, Union
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.config import DATABASE_URI
from config.mybank_db import Users, SecurityLogs
from security.audit import log_operation, log_security_event

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)


class WebAuthnManager:
    """WebAuthn身份验证管理器"""

    def __init__(self, rp_id: str, rp_name: str):
        """
        初始化WebAuthn管理器

        参数:
        - rp_id: 依赖方ID（通常是域名）
        - rp_name: 依赖方名称
        """
        self.rp_id = rp_id
        self.rp_name = rp_name

    def generate_registration_options(self, user_id: str, username: str) -> Dict[str, Any]:
        """
        生成注册选项

        参数:
        - user_id: 用户ID
        - username: 用户名

        返回:
        - 注册选项JSON
        """
        # 生成随机挑战
        challenge = os.urandom(32)
        challenge_b64 = base64.b64encode(challenge).decode('ascii')

        # 模拟注册选项
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

        # 存储挑战以供后续验证
        session = Session()
        try:
            user = session.query(Users).filter_by(user_id=user_id).first()
            if user:
                if not hasattr(user, 'webauthn_data'):
                    # 确保数据库有此字段
                    pass
                else:
                    # 存储挑战
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
        验证注册响应

        参数:
        - user_id: 用户ID
        - credential: 凭证数据

        返回:
        - 验证结果
        """
        session = Session()
        try:
            user = session.query(Users).filter_by(user_id=user_id).first()
            if not user:
                raise ValueError("User not found")

            # 提取已存储的挑战
            webauthn_data = json.loads(user.webauthn_data) if user.webauthn_data else {}
            stored_challenge = webauthn_data.get('registration_challenge')

            if not stored_challenge:
                raise ValueError("No registration challenge found")

            # 验证挑战是否匹配
            client_challenge = credential.get('response', {}).get('clientDataJSON', {}).get('challenge')
            if client_challenge != stored_challenge:
                raise ValueError("Challenge mismatch")

            # 提取凭证ID和公钥
            credential_id = credential.get('id')
            public_key = credential.get('response', {}).get('attestationObject', {}).get('authData', {}).get(
                'attestedCredentialData', {}).get('credentialPublicKey')

            # 存储凭证
            credentials = webauthn_data.get('credentials', [])
            credentials.append({
                'id': credential_id,
                'publicKey': public_key,
                'type': 'public-key',
                'registeredAt': datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
            })

            webauthn_data['credentials'] = credentials
            webauthn_data.pop('registration_challenge', None)  # 移除挑战
            webauthn_data.pop('registration_challenge_time', None)

            user.webauthn_data = json.dumps(webauthn_data)
            session.commit()

            # 记录操作
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
        生成认证选项

        参数:
        - username: 用户名

        返回:
        - 认证选项JSON
        """
        session = Session()
        try:
            user = session.query(Users).filter_by(email=username).first()
            if not user:
                raise ValueError("User not found")

            # 提取已存储的凭证
            webauthn_data = json.loads(user.webauthn_data) if user.webauthn_data else {}
            credentials = webauthn_data.get('credentials', [])

            if not credentials:
                raise ValueError("No credentials found")

            # 生成随机挑战
            challenge = os.urandom(32)
            challenge_b64 = base64.b64encode(challenge).decode('ascii')

            # 在实际实现中，这里会调用FIDO2库
            # options = self.server.authenticate_begin(credentials)

            # 模拟认证选项
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

            # 存储挑战以供后续验证
            webauthn_data['authentication_challenge'] = challenge_b64
            webauthn_data['authentication_challenge_time'] = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
            user.webauthn_data = json.dumps(webauthn_data)
            session.commit()

            return options
        finally:
            session.close()

    def verify_authentication(self, username: str, credential: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证认证响应

        参数:
        - username: 用户名
        - credential: 凭证数据

        返回:
        - 验证结果
        """
        session = Session()
        try:
            user = session.query(Users).filter_by(email=username).first()
            if not user:
                raise ValueError("User not found")

            # 提取已存储的挑战和凭证
            webauthn_data = json.loads(user.webauthn_data) if user.webauthn_data else {}
            stored_challenge = webauthn_data.get('authentication_challenge')

            if not stored_challenge:
                raise ValueError("No authentication challenge found")

            # 验证挑战是否匹配
            client_challenge = credential.get('response', {}).get('clientDataJSON', {}).get('challenge')
            if client_challenge != stored_challenge:
                raise ValueError("Challenge mismatch")

            # 在实际实现中，这里会调用FIDO2库进行完整验证
            # result = self.server.authenticate_complete(
            #    session['authentication_state'],
            #    credentials,
            #    credential.get('clientData'),
            #    credential.get('authenticatorData'),
            #    credential.get('signature')
            # )

            # 模拟验证成功
            # 在实际实现中，这里应该进行完整的签名验证

            # 清除挑战
            webauthn_data.pop('authentication_challenge', None)
            webauthn_data.pop('authentication_challenge_time', None)
            user.webauthn_data = json.dumps(webauthn_data)
            session.commit()

            # 记录操作
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


# 创建WebAuthn管理器实例
webauthn_manager = WebAuthnManager('bankingsystem.example.com', 'MyBank')


def register_webauthn_credential(user_id: str, username: str) -> Dict[str, Any]:
    """注册WebAuthn凭证"""
    return webauthn_manager.generate_registration_options(user_id, username)


def verify_webauthn_registration(user_id: str, credential: Dict[str, Any]) -> Dict[str, Any]:
    """验证WebAuthn注册"""
    return webauthn_manager.verify_registration(user_id, credential)


def authenticate_with_webauthn(username: str) -> Dict[str, Any]:
    """使用WebAuthn进行身份验证"""
    return webauthn_manager.generate_authentication_options(username)


def verify_webauthn_authentication(username: str, credential: Dict[str, Any]) -> Dict[str, Any]:
    """验证WebAuthn身份验证"""
    return webauthn_manager.verify_authentication(username, credential)