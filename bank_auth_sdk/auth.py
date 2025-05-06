import boto3
import jwt
import datetime
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key


class BankAuth:
    def __init__(self, api_name):
        self.api_name = api_name
        self.secrets = boto3.client('secretsmanager', region_name='us-east-1')
        self.kms = boto3.client('kms', region_name='us-east-1')
        self.config = self._load_config()
    
    def _load_config(self):
        secret = self.secrets.get_secret_value(SecretId=f"bank-api/{self.api_name}-app")
        return json.loads(secret['SecretString'])
    
    def generate_token(self):
        headers = {
            "kid": self.config['kms-key-id'],
            "alg": "RS256",
            "typ": "JWT"
        }

        payload = {
            "iss": self.api_name,
            "iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            "exp": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 15 * 60,
            "aud": "bank-internal-apis"
        }

        def b64url_encode(data):
            return base64.urlsafe_b64encode(data).decode('utf-8').rstrip("=")

        header_json = json.dumps(headers, separators=(',', ':')).encode()
        payload_json = json.dumps(payload, separators=(',', ':')).encode()

        message = b64url_encode(header_json) + "." + b64url_encode(payload_json)

        signing_response = self.kms.sign(
            KeyId=self.config['kms-key-id'],
            Message=message.encode(),
            MessageType='RAW',
            SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256'
        )

        signature_b64 = b64url_encode(signing_response['Signature'])

        return f"{message}.{signature_b64}"
    
    def verify_token(self, token):
        try:
            headers = jwt.get_unverified_header(token)
            if headers['kid'] != self.config['kms-key-id']:
                raise ValueError("Token no fue firmado con la key de esta API")
            
            # Obtener clave pública desde KMS y cargarla correctamente
            public_key_response = self.kms.get_public_key(KeyId=headers['kid'])
            public_key_der = public_key_response['PublicKey']
            public_key = load_der_public_key(public_key_der, backend=default_backend())
            
            return jwt.decode(token, public_key, algorithms=["RS256"], audience="bank-internal-apis")
        except Exception as e:
            raise ValueError(f"Verificación fallida: {str(e)}")