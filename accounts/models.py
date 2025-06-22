"""
Modèles pour le système d'authentification sécurisé de GalSecVote
Implémentation des exigences d'authentification forte et de contrôle d'accès
"""

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.core.validators import RegexValidator
from cryptography.fernet import Fernet
import pyotp
import secrets
import hashlib
from datetime import timedelta


class User(AbstractUser):
    """
    Modèle utilisateur personnalisé avec fonctionnalités de sécurité renforcées
    Exigence: Authentification forte 2FA + contrôle d'accès
    """
    
    # Champs additionnels de sécurité
    email = models.EmailField(unique=True, verbose_name="Adresse email")
    phone_number = models.CharField(
        max_length=15, 
        blank=True, 
        validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Format de téléphone invalide")]
    )
    
    # Statuts de sécurité
    is_verified = models.BooleanField(default=False, verbose_name="Email vérifié")
    is_2fa_enabled = models.BooleanField(default=False, verbose_name="2FA activé")
    is_locked = models.BooleanField(default=False, verbose_name="Compte verrouillé")
    
    # Métadonnées de sécurité
    last_password_change = models.DateTimeField(auto_now_add=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    lockout_until = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    
    # Rôles pour l'autorisation
    ROLE_CHOICES = [
        ('voter', 'Électeur'),
        ('admin', 'Administrateur'),
        ('supervisor', 'Superviseur'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='voter')
    
    # Métadonnées d'audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    class Meta:
        verbose_name = "Utilisateur"
        verbose_name_plural = "Utilisateurs"
        permissions = [
            ("can_manage_elections", "Peut gérer les élections"),
            ("can_view_audit_logs", "Peut consulter les journaux d'audit"),
            ("can_manage_users", "Peut gérer les utilisateurs"),
        ]
    
    def __str__(self):
        return f"{self.username} ({self.email})"
    
    def is_account_locked(self):
        """Vérifie si le compte est verrouillé"""
        if self.is_locked:
            return True
        if self.lockout_until and timezone.now() < self.lockout_until:
            return True
        return False
    
    def increment_failed_login(self):
        """Incrémente les tentatives de connexion échouées"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # MAX_LOGIN_ATTEMPTS from settings
            self.lockout_until = timezone.now() + timedelta(minutes=15)
        self.save()
    
    def reset_failed_login(self):
        """Remet à zéro les tentatives de connexion échouées"""
        self.failed_login_attempts = 0
        self.lockout_until = None
        self.save()
    
    def can_vote_in_election(self, election):
        """Vérifie si l'utilisateur peut voter dans une élection"""
        if not self.is_verified or self.is_account_locked():
            return False
        return election.is_user_eligible(self)


class UserProfile(models.Model):
    """
    Profil utilisateur avec informations additionnelles
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Informations personnelles (optionnelles)
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    
    # Préférences de sécurité
    notification_email = models.BooleanField(default=True)
    notification_sms = models.BooleanField(default=False)
    session_timeout_preference = models.PositiveIntegerField(default=30)  # minutes
    
    # Métadonnées
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Profil de {self.user.username}"


class TwoFactorAuth(models.Model):
    """
    Gestion de l'authentification à deux facteurs
    Exigence: Authentification 2FA obligatoire
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='two_factor')
    
    # Secret TOTP chiffré
    secret_key = models.CharField(max_length=255)  # Stocké chiffré
    backup_tokens = models.JSONField(default=list)  # Tokens de récupération chiffrés
    
    # Statuts
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    
    def generate_secret(self):
        """Génère un nouveau secret TOTP"""
        secret = pyotp.random_base32()
        # TODO: Chiffrer le secret avant stockage
        self.secret_key = secret
        return secret
    
    def get_totp_uri(self):
        """Génère l'URI TOTP pour les applications d'authentification"""
        totp = pyotp.TOTP(self.secret_key)
        return totp.provisioning_uri(
            name=self.user.email,
            issuer_name="GalSecVote"
        )
    
    def verify_token(self, token):
        """Vérifie un token TOTP"""
        totp = pyotp.TOTP(self.secret_key)
        is_valid = totp.verify(token, valid_window=2)  # Fenêtre de 2*30s
        
        if is_valid:
            self.last_used = timezone.now()
            self.save()
        
        return is_valid
    
    def generate_backup_tokens(self, count=10):
        """Génère des tokens de récupération"""
        tokens = [secrets.token_hex(8) for _ in range(count)]
        # TODO: Chiffrer les tokens avant stockage
        self.backup_tokens = tokens
        self.save()
        return tokens
    
    def use_backup_token(self, token):
        """Utilise un token de récupération"""
        if token in self.backup_tokens:
            self.backup_tokens.remove(token)
            self.save()
            return True
        return False


class UserSession(models.Model):
    """
    Gestion sécurisée des sessions utilisateur
    Exigence: Contrôle des sessions et déconnexion automatique
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40, unique=True)
    
    # Informations de session
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    device_fingerprint = models.CharField(max_length=64, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    
    # Statuts de sécurité
    is_active = models.BooleanField(default=True)
    is_suspicious = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-last_activity']
    
    def __str__(self):
        return f"Session {self.user.username} - {self.ip_address}"
    
    def is_expired(self):
        """Vérifie si la session a expiré"""
        return timezone.now() > self.expires_at
    
    def extend_session(self, minutes=30):
        """Prolonge la session"""
        self.expires_at = timezone.now() + timedelta(minutes=minutes)
        self.last_activity = timezone.now()
        self.save()
    
    def invalidate(self):
        """Invalide la session"""
        self.is_active = False
        self.save()
    
    @classmethod
    def cleanup_expired_sessions(cls):
        """Nettoie les sessions expirées"""
        expired_sessions = cls.objects.filter(
            expires_at__lt=timezone.now()
        )
        count = expired_sessions.count()
        expired_sessions.delete()
        return count


class PasswordHistory(models.Model):
    """
    Historique des mots de passe pour éviter la réutilisation
    Exigence: Politique de mots de passe renforcée
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_history')
    password_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    @classmethod
    def add_password(cls, user, password):
        """Ajoute un mot de passe à l'historique"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        cls.objects.create(user=user, password_hash=password_hash)
        
        # Garder seulement les 5 derniers mots de passe
        old_passwords = cls.objects.filter(user=user)[5:]
        cls.objects.filter(id__in=[p.id for p in old_passwords]).delete()
    
    @classmethod
    def is_password_reused(cls, user, password):
        """Vérifie si le mot de passe a déjà été utilisé"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return cls.objects.filter(
            user=user, 
            password_hash=password_hash
        ).exists()


class UserPermission(models.Model):
    """
    Permissions granulaires pour les utilisateurs
    Exigence: Contrôle d'accès fin (DAC)
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='custom_permissions')
    
    # Types de permissions
    PERMISSION_TYPES = [
        ('election.create', 'Créer une élection'),
        ('election.manage', 'Gérer une élection'),
        ('election.view', 'Voir une élection'),
        ('vote.cast', 'Voter'),
        ('audit.view', 'Voir les audits'),
        ('user.manage', 'Gérer les utilisateurs'),
    ]
    
    permission_type = models.CharField(max_length=50, choices=PERMISSION_TYPES)
    object_id = models.PositiveIntegerField(null=True, blank=True)  # ID de l'objet spécifique
    
    # Métadonnées
    granted_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='granted_permissions')
    granted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        unique_together = ['user', 'permission_type', 'object_id']
    
    def __str__(self):
        return f"{self.user.username} - {self.permission_type}"
    
    def is_valid(self):
        """Vérifie si la permission est valide"""
        if not self.is_active:
            return False
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        return True