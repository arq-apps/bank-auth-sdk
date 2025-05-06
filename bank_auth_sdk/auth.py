import boto3
import jwt
import datetime
import json
from cryptography.hazmat.primitives import serialization

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
        headers = {"kid": self.config['kms-key-id'], "alg": "RS256"}
        payload = {
            "iss": self.api_name,
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
            "aud": "bank-internal-apis"
        }
        signing_response = self.kms.sign(
            KeyId=self.config['kms-key-id'],
            Message=json.dumps(payload),
            MessageType='RAW',
            SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256'
        )
        return jwt.encode(payload, signing_response['Signature'], algorithm="RS256", headers=headers)
    
    def verify_token(self, token):
        try:
            headers = jwt.get_unverified_header(token)
            if headers['kid'] != self.config['kms-key-id']:
                raise ValueError("Token no fue firmado con la key de esta API")
            public_key = self.kms.get_public_key(KeyId=headers['kid'])
            return jwt.decode(token, public_key, algorithms=["RS256"], audience="bank-internal-apis")
        except Exception as e:
            raise ValueError(f"Verificación fallida: {str(e)}")