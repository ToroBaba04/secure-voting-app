"""
Gestionnaire RSA pour le chiffrement et les signatures numériques
Implémentation des exigences de chiffrement asymétrique de GalSecVote
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
import secrets
import hashlib
from typing import Tuple, Optional
import logging

logger = logging.getLogger('cryptoutils')


class RSAManager:
    """
    Gestionnaire pour les opérations RSA (chiffrement, déchiffrement, signature)
    Exigence: Chiffrement asymétrique sécurisé pour les bulletins de vote
    """
    
    def __init__(self, key_size: int = 2048):
        """
        Initialise le gestionnaire RSA
        
        Args:
            key_size: Taille de la clé en bits (2048, 3072, 4096)
        """
        self.key_size = key_size
        self.padding_scheme = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
        self.signature_padding = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )
    
    def generate_key_pair(self) -> Tuple[str, str]:
        """
        Génère une nouvelle paire de clés RSA
        
        Returns:
            Tuple[str, str]: (clé_publique_pem, clé_privée_pem)
        """
        try:
            # Générer la clé privée
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend()
            )
            
            # Extraire la clé publique
            public_key = private_key.public_key()
            
            # Sérialiser la clé publique
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Sérialiser la clé privée (sans chiffrement pour le moment)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            logger.info(f"Nouvelle paire de clés RSA générée ({self.key_size} bits)")
            return public_pem, private_pem
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération des clés RSA: {e}")
            raise
    
    def encrypt_data(self, data: str, public_key_pem: str) -> str:
        """
        Chiffre des données avec une clé publique RSA
        
        Args:
            data: Données à chiffrer (string)
            public_key_pem: Clé publique au format PEM
            
        Returns:
            str: Données chiffrées encodées en base64
        """
        try:
            # Charger la clé publique
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Convertir les données en bytes
            data_bytes = data.encode('utf-8')
            
            # Chiffrer les données
            encrypted_data = public_key.encrypt(data_bytes, self.padding_scheme)
            
            # Encoder en base64 pour stockage
            encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
            
            logger.debug(f"Données chiffrées avec succès ({len(data)} caractères)")
            return encrypted_b64
            
        except Exception as e:
            logger.error(f"Erreur lors du chiffrement RSA: {e}")
            raise
    
    def decrypt_data(self, encrypted_data_b64: str, private_key_pem: str) -> str:
        """
        Déchiffre des données avec une clé privée RSA
        
        Args:
            encrypted_data_b64: Données chiffrées encodées en base64
            private_key_pem: Clé privée au format PEM
            
        Returns:
            str: Données déchiffrées
        """
        try:
            # Charger la clé privée
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,  # TODO: Ajouter support pour mots de passe
                backend=default_backend()
            )
            
            # Décoder de base64
            encrypted_data = base64.b64decode(encrypted_data_b64.encode('utf-8'))
            
            # Déchiffrer les données
            decrypted_data = private_key.decrypt(encrypted_data, self.padding_scheme)
            
            # Convertir en string
            decrypted_text = decrypted_data.decode('utf-8')
            
            logger.debug("Données déchiffrées avec succès")
            return decrypted_text
            
        except Exception as e:
            logger.error(f"Erreur lors du déchiffrement RSA: {e}")
            raise
    
    def sign_data(self, data: str, private_key_pem: str) -> str:
        """
        Signe des données avec une clé privée RSA
        
        Args:
            data: Données à signer
            private_key_pem: Clé privée au format PEM
            
        Returns:
            str: Signature encodée en base64
        """
        try:
            # Charger la clé privée
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            # Convertir les données en bytes
            data_bytes = data.encode('utf-8')
            
            # Signer les données
            signature = private_key.sign(data_bytes, self.signature_padding, hashes.SHA256())
            
            # Encoder en base64
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            logger.debug(f"Données signées avec succès ({len(data)} caractères)")
            return signature_b64
            
        except Exception as e:
            logger.error(f"Erreur lors de la signature RSA: {e}")
            raise
    
    def verify_signature(self, data: str, signature_b64: str, public_key_pem: str) -> bool:
        """
        Vérifie une signature RSA
        
        Args:
            data: Données originales
            signature_b64: Signature encodée en base64
            public_key_pem: Clé publique au format PEM
            
        Returns:
            bool: True si la signature est valide
        """
        try:
            # Charger la clé publique
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Décoder la signature
            signature = base64.b64decode(signature_b64.encode('utf-8'))
            
            # Convertir les données en bytes
            data_bytes = data.encode('utf-8')
            
            # Vérifier la signature
            public_key.verify(signature, data_bytes, self.signature_padding, hashes.SHA256())
            
            logger.debug("Signature vérifiée avec succès")
            return True
            
        except InvalidSignature:
            logger.warning("Signature invalide détectée")
            return False
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de signature: {e}")
            return False
    
    def get_key_fingerprint(self, public_key_pem: str) -> str:
        """
        Calcule l'empreinte d'une clé publique
        
        Args:
            public_key_pem: Clé publique au format PEM
            
        Returns:
            str: Empreinte SHA256 de la clé
        """
        try:
            # Normaliser la clé (enlever whitespace)
            key_normalized = ''.join(public_key_pem.split())
            
            # Calculer le hash SHA256
            fingerprint = hashlib.sha256(key_normalized.encode('utf-8')).hexdigest()
            
            # Formater l'empreinte (groupes de 2 caractères séparés par :)
            formatted_fingerprint = ':'.join([fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)])
            
            return formatted_fingerprint
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul d'empreinte: {e}")
            raise
    
    def get_key_info(self, key_pem: str, is_private: bool = False) -> dict:
        """
        Extrait les informations d'une clé RSA
        
        Args:
            key_pem: Clé au format PEM
            is_private: True si c'est une clé privée
            
        Returns:
            dict: Informations sur la clé
        """
        try:
            if is_private:
                key = serialization.load_pem_private_key(
                    key_pem.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                public_key = key.public_key()
            else:
                public_key = serialization.load_pem_public_key(
                    key_pem.encode('utf-8'),
                    backend=default_backend()
                )
            
            # Extraire les informations
            key_size = public_key.key_size
            public_numbers = public_key.public_numbers()
            
            return {
                'key_size': key_size,
                'public_exponent': public_numbers.e,
                'algorithm': 'RSA',
                'is_private': is_private,
                'fingerprint': self.get_key_fingerprint(key_pem if not is_private else 
                    public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8'))
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction d'informations de clé: {e}")
            raise
    
    @staticmethod
    def generate_random_key_id() -> str:
        """
        Génère un ID aléatoire pour une clé
        
        Returns:
            str: ID unique de 32 caractères hexadécimaux
        """
        return secrets.token_hex(16)
    
    def encrypt_large_data(self, data: str, public_key_pem: str) -> str:
        """
        Chiffre de gros volumes de données en utilisant le chiffrement hybride
        (RSA + AES pour contourner les limites de taille RSA)
        
        Args:
            data: Données à chiffrer
            public_key_pem: Clé publique RSA
            
        Returns:
            str: Données chiffrées (clé AES chiffrée + données chiffrées AES)
        """
        try:
            from cryptography.fernet import Fernet
            
            # Générer une clé AES aléatoire
            aes_key = Fernet.generate_key()
            fernet = Fernet(aes_key)
            
            # Chiffrer les données avec AES
            encrypted_data = fernet.encrypt(data.encode('utf-8'))
            
            # Chiffrer la clé AES avec RSA
            encrypted_aes_key = self.encrypt_data(aes_key.decode('utf-8'), public_key_pem)
            
            # Combiner : clé_chiffrée + séparateur + données_chiffrées
            result = f"{encrypted_aes_key}||{base64.b64encode(encrypted_data).decode('utf-8')}"
            
            logger.debug(f"Chiffrement hybride réussi pour {len(data)} caractères")
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors du chiffrement hybride: {e}")
            raise
    
    def decrypt_large_data(self, encrypted_data: str, private_key_pem: str) -> str:
        """
        Déchiffre des données chiffrées avec le chiffrement hybride
        
        Args:
            encrypted_data: Données chiffrées (format hybride)
            private_key_pem: Clé privée RSA
            
        Returns:
            str: Données déchiffrées
        """
        try:
            from cryptography.fernet import Fernet
            
            # Séparer la clé chiffrée et les données chiffrées
            parts = encrypted_data.split('||', 1)
            if len(parts) != 2:
                raise ValueError("Format de données chiffrées invalide")
            
            encrypted_aes_key, encrypted_data_b64 = parts
            
            # Déchiffrer la clé AES avec RSA
            aes_key = self.decrypt_data(encrypted_aes_key, private_key_pem)
            fernet = Fernet(aes_key.encode('utf-8'))
            
            # Déchiffrer les données avec AES
            encrypted_data_bytes = base64.b64decode(encrypted_data_b64.encode('utf-8'))
            decrypted_data = fernet.decrypt(encrypted_data_bytes)
            
            result = decrypted_data.decode('utf-8')
            logger.debug("Déchiffrement hybride réussi")
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors du déchiffrement hybride: {e}")
            raise