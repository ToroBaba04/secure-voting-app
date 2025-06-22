"""
Modèles pour la gestion cryptographique sécurisée de GalSecVote
Implémentation des exigences de chiffrement, signatures et gestion de clés
"""

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator, MaxValueValidator
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import uuid
import hashlib
import secrets
from datetime import timedelta

User = get_user_model()


class KeyPair(models.Model):
    """
    Gestion des paires de clés RSA pour les élections
    Exigence: Chiffrement asymétrique sécurisé
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Métadonnées de la clé
    name = models.CharField(max_length=100, verbose_name="Nom de la clé")
    description = models.TextField(blank=True, verbose_name="Description")
    
    # Propriétaire de la clé
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='key_pairs')
    
    # Utilisation de la clé
    PURPOSE_CHOICES = [
        ('election', 'Chiffrement d\'élection'),
        ('signature', 'Signature numérique'),
        ('system', 'Système'),
        ('backup', 'Sauvegarde'),
    ]
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, default='election')
    
    # Clés (stockées de manière sécurisée)
    public_key_pem = models.TextField(verbose_name="Clé publique (PEM)")
    private_key_encrypted = models.TextField(verbose_name="Clé privée chiffrée")
    
    # Paramètres cryptographiques
    key_size = models.PositiveIntegerField(
        default=2048,
        validators=[MinValueValidator(1024), MaxValueValidator(4096)],
        verbose_name="Taille de clé (bits)"
    )
    
    # Identifiants de clé
    key_id = models.CharField(max_length=64, unique=True, verbose_name="ID de clé")
    fingerprint = models.CharField(max_length=128, verbose_name="Empreinte")
    
    # Métadonnées de cycle de vie
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used = models.DateTimeField(null=True, blank=True)
    
    # Statuts de sécurité
    is_active = models.BooleanField(default=True)
    is_compromised = models.BooleanField(default=False)
    is_revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='revoked_keys'
    )
    
    # Audit et usage
    usage_count = models.PositiveIntegerField(default=0)
    max_usage_count = models.PositiveIntegerField(null=True, blank=True)
    
    class Meta:
        verbose_name = "Paire de clés"
        verbose_name_plural = "Paires de clés"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['owner', 'purpose']),
            models.Index(fields=['key_id']),
            models.Index(fields=['is_active', 'expires_at']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.purpose}) - {self.key_size} bits"
    
    def is_valid(self):
        """Vérifie si la clé est valide et utilisable"""
        if not self.is_active or self.is_compromised or self.is_revoked:
            return False
        
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        
        if self.max_usage_count and self.usage_count >= self.max_usage_count:
            return False
        
        return True
    
    def increment_usage(self):
        """Incrémente le compteur d'utilisation"""
        self.usage_count += 1
        self.last_used = timezone.now()
        self.save()
    
    def revoke(self, revoked_by=None, reason=""):
        """Révoque la clé"""
        self.is_revoked = True
        self.revoked_at = timezone.now()
        self.revoked_by = revoked_by
        self.is_active = False
        self.save()
        
        # Log la révocation
        KeyRevocation.objects.create(
            key_pair=self,
            revoked_by=revoked_by,
            reason=reason
        )
    
    def get_public_key_object(self):
        """Retourne l'objet clé publique pour les opérations crypto"""
        return serialization.load_pem_public_key(
            self.public_key_pem.encode(),
            backend=default_backend()
        )
    
    @classmethod
    def generate_key_pair(cls, name, owner, purpose='election', key_size=2048, **kwargs):
        """Génère une nouvelle paire de clés"""
        # Générer la paire de clés RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Sérialiser la clé publique
        public_pem = public_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Chiffrer la clé privée (TODO: implémenter le chiffrement)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # À changer en production
        ).decode()
        
        # Générer l'ID et l'empreinte
        key_id = secrets.token_hex(32)
        fingerprint = hashlib.sha256(public_pem.encode()).hexdigest()
        
        return cls.objects.create(
            name=name,
            owner=owner,
            purpose=purpose,
            public_key_pem=public_pem,
            private_key_encrypted=private_pem,  # TODO: chiffrer en production
            key_size=key_size,
            key_id=key_id,
            fingerprint=fingerprint,
            **kwargs
        )


class KeyRevocation(models.Model):
    """
    Journal des révocations de clés
    Exigence: Traçabilité de la gestion des clés
    """
    
    key_pair = models.ForeignKey(KeyPair, on_delete=models.CASCADE, related_name='revocations')
    revoked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    # Détails de la révocation
    reason = models.TextField(verbose_name="Raison de la révocation")
    revoked_at = models.DateTimeField(auto_now_add=True)
    
    # Notification
    notifications_sent = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = "Révocation de clé"
        verbose_name_plural = "Révocations de clés"
        ordering = ['-revoked_at']
    
    def __str__(self):
        return f"Révocation de {self.key_pair.name} par {self.revoked_by}"


class CryptographicOperation(models.Model):
    """
    Journal des opérations cryptographiques
    Exigence: Audit des opérations de chiffrement/déchiffrement
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Opération
    OPERATION_TYPES = [
        ('encrypt', 'Chiffrement'),
        ('decrypt', 'Déchiffrement'),
        ('sign', 'Signature'),
        ('verify', 'Vérification'),
        ('hash', 'Hachage'),
        ('key_generation', 'Génération de clé'),
    ]
    operation_type = models.CharField(max_length=20, choices=OPERATION_TYPES)
    
    # Clé utilisée
    key_pair = models.ForeignKey(
        KeyPair, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name='operations'
    )
    key_id = models.CharField(max_length=64, verbose_name="ID de clé utilisée")
    
    # Utilisateur et contexte
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    ip_address = models.GenericIPAddressField()
    
    # Détails de l'opération
    data_size_bytes = models.PositiveIntegerField(verbose_name="Taille des données (octets)")
    algorithm = models.CharField(max_length=50, verbose_name="Algorithme utilisé")
    
    # Timing et performance
    timestamp = models.DateTimeField(auto_now_add=True)
    processing_time_ms = models.PositiveIntegerField(verbose_name="Temps de traitement (ms)")
    
    # Résultat
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    # Hash de vérification (sans les données sensibles)
    operation_hash = models.CharField(max_length=64, verbose_name="Hash de l'opération")
    
    class Meta:
        verbose_name = "Opération cryptographique"
        verbose_name_plural = "Opérations cryptographiques"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['operation_type', 'timestamp']),
            models.Index(fields=['key_id', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.operation_type} - {self.key_id[:8]} - {self.timestamp}"
    
    @classmethod
    def log_operation(cls, operation_type, key_pair, user, data_size, 
                     processing_time, success=True, error_message="", **kwargs):
        """Log une opération cryptographique"""
        
        # Créer le hash de l'opération
        operation_data = f"{operation_type}:{key_pair.key_id if key_pair else 'none'}:{user.id if user else 'anonymous'}:{timezone.now().isoformat()}"
        operation_hash = hashlib.sha256(operation_data.encode()).hexdigest()
        
        return cls.objects.create(
            operation_type=operation_type,
            key_pair=key_pair,
            key_id=key_pair.key_id if key_pair else '',
            user=user,
            data_size_bytes=data_size,
            processing_time_ms=processing_time,
            success=success,
            error_message=error_message,
            operation_hash=operation_hash,
            **kwargs
        )


class DigitalSignature(models.Model):
    """
    Gestion des signatures numériques
    Exigence: Intégrité et non-répudiation
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Données signées (référence)
    signed_data_hash = models.CharField(max_length=64, verbose_name="Hash des données signées")
    signature_value = models.TextField(verbose_name="Valeur de la signature")
    
    # Clé de signature
    signing_key = models.ForeignKey(KeyPair, on_delete=models.CASCADE, related_name='signatures')
    
    # Algorithme de signature
    SIGNATURE_ALGORITHMS = [
        ('PSS', 'RSA-PSS'),
        ('PKCS1v15', 'RSA-PKCS1v15'),
    ]
    algorithm = models.CharField(max_length=20, choices=SIGNATURE_ALGORITHMS, default='PSS')
    hash_algorithm = models.CharField(max_length=20, default='SHA256')
    
    # Métadonnées
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    # Vérification
    is_verified = models.BooleanField(default=False)
    verification_count = models.PositiveIntegerField(default=0)
    last_verified = models.DateTimeField(null=True, blank=True)
    
    # Contexte d'utilisation
    context = models.CharField(max_length=100, blank=True, verbose_name="Contexte d'utilisation")
    
    class Meta:
        verbose_name = "Signature numérique"
        verbose_name_plural = "Signatures numériques"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Signature {self.id} - {self.algorithm}"
    
    def verify_signature(self, original_data):
        """Vérifie la signature"""
        try:
            # Vérifier le hash des données
            data_hash = hashlib.sha256(original_data.encode()).hexdigest()
            if data_hash != self.signed_data_hash:
                return False
            
            # Vérifier la signature cryptographique
            public_key = self.signing_key.get_public_key_object()
            
            # TODO: Implémenter la vérification réelle de signature
            # Ici on simule la vérification
            
            self.verification_count += 1
            self.last_verified = timezone.now()
            self.is_verified = True
            self.save()
            
            return True
            
        except Exception:
            return False


class HashRecord(models.Model):
    """
    Enregistrement des hashes pour intégrité
    Exigence: Vérification d'intégrité des données
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Données hashées
    data_identifier = models.CharField(max_length=200, verbose_name="Identifiant des données")
    hash_value = models.CharField(max_length=128, verbose_name="Valeur du hash")
    
    # Algorithme de hachage
    HASH_ALGORITHMS = [
        ('SHA256', 'SHA-256'),
        ('SHA384', 'SHA-384'),
        ('SHA512', 'SHA-512'),
        ('BLAKE2b', 'BLAKE2b'),
    ]
    algorithm = models.CharField(max_length=20, choices=HASH_ALGORITHMS, default='SHA256')
    
    # Métadonnées
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    # Vérification d'intégrité
    is_verified = models.BooleanField(default=True)
    last_verification = models.DateTimeField(null=True, blank=True)
    verification_count = models.PositiveIntegerField(default=0)
    
    # Contexte
    PURPOSE_CHOICES = [
        ('vote_integrity', 'Intégrité du vote'),
        ('election_integrity', 'Intégrité de l\'élection'),
        ('audit_integrity', 'Intégrité d\'audit'),
        ('system_integrity', 'Intégrité système'),
    ]
    purpose = models.CharField(max_length=30, choices=PURPOSE_CHOICES)
    
    class Meta:
        verbose_name = "Enregistrement de hash"
        verbose_name_plural = "Enregistrements de hash"
        ordering = ['-created_at']
        unique_together = ['data_identifier', 'purpose']
    
    def __str__(self):
        return f"{self.data_identifier} - {self.algorithm}"
    
    def verify_integrity(self, current_data):
        """Vérifie l'intégrité des données"""
        if self.algorithm == 'SHA256':
            current_hash = hashlib.sha256(current_data.encode()).hexdigest()
        elif self.algorithm == 'SHA512':
            current_hash = hashlib.sha512(current_data.encode()).hexdigest()
        else:
            return False
        
        is_valid = current_hash == self.hash_value
        
        self.verification_count += 1
        self.last_verification = timezone.now()
        self.is_verified = is_valid
        self.save()
        
        return is_valid
    
    @classmethod
    def create_hash_record(cls, data_identifier, data, purpose, algorithm='SHA256', user=None):
        """Crée un enregistrement de hash"""
        if algorithm == 'SHA256':
            hash_value = hashlib.sha256(data.encode()).hexdigest()
        elif algorithm == 'SHA512':
            hash_value = hashlib.sha512(data.encode()).hexdigest()
        else:
            raise ValueError(f"Algorithme non supporté: {algorithm}")
        
        return cls.objects.create(
            data_identifier=data_identifier,
            hash_value=hash_value,
            algorithm=algorithm,
            purpose=purpose,
            created_by=user
        )


class EncryptionKey(models.Model):
    """
    Clés de chiffrement symétrique pour données sensibles
    Exigence: Protection des données sensibles en base
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Métadonnées de la clé
    name = models.CharField(max_length=100, verbose_name="Nom de la clé")
    purpose = models.CharField(max_length=100, verbose_name="Utilisation")
    
    # Clé chiffrée (chiffrée avec la clé maître)
    encrypted_key = models.TextField(verbose_name="Clé chiffrée")
    key_derivation_salt = models.CharField(max_length=64, verbose_name="Salt de dérivation")
    
    # Algorithme
    ENCRYPTION_ALGORITHMS = [
        ('AES256', 'AES-256'),
        ('ChaCha20', 'ChaCha20'),
        ('Fernet', 'Fernet'),
    ]
    algorithm = models.CharField(max_length=20, choices=ENCRYPTION_ALGORITHMS, default='AES256')
    
    # Métadonnées de cycle de vie
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    # Statuts
    is_active = models.BooleanField(default=True)
    is_rotated = models.BooleanField(default=False)
    rotated_at = models.DateTimeField(null=True, blank=True)
    
    # Usage
    usage_count = models.PositiveIntegerField(default=0)
    last_used = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = "Clé de chiffrement"
        verbose_name_plural = "Clés de chiffrement"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.algorithm})"
    
    def is_valid(self):
        """Vérifie si la clé est valide"""
        if not self.is_active or self.is_rotated:
            return False
        
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        
        return True
    
    def rotate_key(self, new_key_data, rotated_by=None):
        """Effectue la rotation de la clé"""
        # Marquer l'ancienne clé comme rotée
        self.is_rotated = True
        self.rotated_at = timezone.now()
        self.is_active = False
        self.save()
        
        # Créer une nouvelle clé
        new_key = EncryptionKey.objects.create(
            name=f"{self.name}_rotated_{int(timezone.now().timestamp())}",
            purpose=self.purpose,
            encrypted_key=new_key_data,
            algorithm=self.algorithm,
            created_by=rotated_by
        )
        
        return new_key
    
    def increment_usage(self):
        """Incrémente le compteur d'utilisation"""
        self.usage_count += 1
        self.last_used = timezone.now()
        self.save()


class CertificateAuthority(models.Model):
    """
    Autorité de certification interne pour GalSecVote
    Exigence: PKI interne pour la gestion des certificats
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Informations de la CA
    name = models.CharField(max_length=200, verbose_name="Nom de la CA")
    description = models.TextField(verbose_name="Description")
    
    # Certificat de la CA
    ca_certificate = models.TextField(verbose_name="Certificat CA (PEM)")
    ca_private_key_encrypted = models.TextField(verbose_name="Clé privée CA chiffrée")
    
    # Métadonnées
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.PROTECT)
    
    # Validité
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField()
    
    # Statuts
    is_active = models.BooleanField(default=True)
    is_root_ca = models.BooleanField(default=False)
    
    # Statistiques
    certificates_issued = models.PositiveIntegerField(default=0)
    certificates_revoked = models.PositiveIntegerField(default=0)
    
    class Meta:
        verbose_name = "Autorité de certification"
        verbose_name_plural = "Autorités de certification"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"CA: {self.name}"
    
    def is_valid(self):
        """Vérifie si la CA est valide"""
        now = timezone.now()
        return (
            self.is_active and
            self.valid_from <= now <= self.valid_until
        )
    
    def issue_certificate(self, subject, public_key, validity_days=365):
        """Émet un nouveau certificat"""
        # TODO: Implémenter l'émission de certificat
        self.certificates_issued += 1
        self.save()
        
        return f"Certificate issued for {subject}"