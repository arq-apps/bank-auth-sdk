from setuptools import setup, find_packages

setup(
    name="bank-auth-sdk",  
    version="0.1.0",
    packages=find_packages(),  
    install_requires=[  
        "boto3>=1.20.0",
        "PyJWT>=2.3.0",
        "cryptography>=3.4.0"
    ],
    python_requires='>=3.6',  
)