# BankAuth SDK

Este módulo proporciona una forma segura y reutilizable de generar y verificar tokens JWT firmados con claves asimétricas de AWS KMS, y configuradas dinámicamente desde AWS Secrets Manager.

---

## 🧱 Rol en la PoC

- Encapsula toda la lógica criptográfica de firma y verificación de JWT.
- Facilita el uso de KMS en APIs como `transactions` y `accounts`, ocultando detalles de implementación.
- Permite controlar la identidad de la API emisora, el tiempo de validez del token y su audiencia (`aud`).

---

## 📦 Funcionalidades

### ✅ `generate_token()`
Genera un JWT firmado con la clave KMS correspondiente, incluyendo:
- `iss` (API emisora)
- `iat` (issued at)
- `exp` (expiración)
- `aud` (audiencia esperada)
- Firma RS256 usando `KMS.sign(...)`

### ✅ `verify_token(token)`
- Decodifica sin verificar para extraer el `kid`.
- Verifica la firma usando la clave pública obtenida con `KMS.get_public_key(...)`.
- Valida expiración (`exp`), audiencia (`aud`), firma y `kid`.

---

## 🔧 Requisitos

- Python 3.8+
- Acceso a AWS Secrets Manager (para obtener el `kms-key-id`)
- Acceso a AWS KMS (para firmar y obtener la clave pública)

---

## ⚙️ Variables de entorno necesarias

| Variable         | Descripción                                                |
|------------------|------------------------------------------------------------|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Credenciales para usar Secrets Manager y KMS |
| `AWS_SESSION_TOKEN`                           | Solo si usás credenciales temporales         |
| `AWS_DEFAULT_REGION`                          | Región AWS donde están las claves y secretos |

---

## 📁 Estructura esperada en Secrets Manager

El secreto `bank-api/<api-name>-app` debe tener el siguiente contenido:

```json
{
  "api-name": "transactions",
  "kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/abcd-efgh-ijkl",
  "rotation": "quarterly"
}
```

---

## 🧪 Ejemplo de uso

```python
from bank_auth_sdk.auth import BankAuth

auth = BankAuth("transactions")
token = auth.generate_token()
print(token)

auth.verify_token(token)  # ✅ No lanza excepción si es válido

```

## Instalacion en local

```bash
pip install -r requirements.txt
```

## Instalacion para usar en un proyecto

```bash
pip install git+https://github.com/bank-api/bank-auth-sdk.git
```




