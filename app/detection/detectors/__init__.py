"""Detector implementations registry."""

from app.detection.detectors.cpf import CPFDetector
from app.detection.detectors.cnpj import CNPJDetector
from app.detection.detectors.credit_card import CreditCardDetector
from app.detection.detectors.email import EmailDetector
from app.detection.detectors.phone import PhoneDetector
from app.detection.detectors.jwt import JWTDetector
from app.detection.detectors.api_key import APIKeyDetector
from app.detection.detectors.credentials import CredentialsDetector

__all__ = [
    "CPFDetector",
    "CNPJDetector",
    "CreditCardDetector",
    "EmailDetector",
    "PhoneDetector",
    "JWTDetector",
    "APIKeyDetector",
    "CredentialsDetector",
]

