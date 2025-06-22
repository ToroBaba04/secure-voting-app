"""
Modèles pour le système d'audit et de traçabilité de GalSecVote
Implémentation des exigences d'audit, responsabilité et conformité
"""

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
import json
import uuid
import hashlib
from datetime import timedelta

User = get_user_model()


class AuditLog(models.Model):
    """
    Journal d'audit principal pour tracer toutes les actions du système
    Exigence: Audit complet et responsabilité des actions
    """
    
    # Identifiant unique
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Qui a fait l'action
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    username = models.CharField(max_length=150, verbose_name="Nom d'utilisateur")  # Backup si user supprimé
    user_ip = models.GenericIPAddressField(verbose_name="Adresse IP")
    user_agent = models.TextField(verbose_name="User Agent")
    session_key = models.CharField(max_length=40, blank=True)
    
    # Quoi
    action = models.CharField(max_length=100, verbose_name="Action")
    resource = models.CharField(max_length=100, verbose_name="Ressource")
    
    # Objet concerné (générique)
    content_type = models.ForeignKey(ContentType, on_delete=models.SET_NULL, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    
    # Détails de l'action
    details = models.JSONField(default=dict, verbose_name="Détails")
    old_values = models.JSONField(default=dict, verbose_name="Anciennes valeurs")
    new_values = models.JSONField(default=dict, verbose_name="Nouvelles valeurs")
    
    # Quand
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Résultat
    RESULT_CHOICES = [
        ('success', 'Succès'),
        ('failure', 'Échec'),
        ('warning', 'Avertissement'),
        ('error', 'Erreur'),
    ]
    result = models.CharField(max_length=20, choices=RESULT_CHOICES, default='success')
    error_message = models.TextField(blank=True)
    
    # Niveau de sévérité
    SEVERITY_CHOICES = [
        ('low', 'Faible'),
        ('medium', 'Moyen'),
        ('high', 'Élevé'),
        ('critical', 'Critique'),
    ]
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    
    # Catégories d'audit
    CATEGORY_CHOICES = [
        ('authentication', 'Authentification'),
        ('authorization', 'Autorisation'),
        ('data_access', 'Accès aux données'),
        ('data_modification', 'Modification des données'),
        ('system_event', 'Événement système'),
        ('security_event', 'Événement de sécurité'),
        ('election_event', 'Événement électoral'),
        ('vote_event', 'Événement de vote'),
    ]
    category = models.CharField(max_length=30, choices=CATEGORY_CHOICES)
    
    # Intégrité
    checksum = models.CharField(max_length=64, verbose_name="Somme de contrôle")
    
    class Meta:
        verbose_name = "Journal d'audit"
        verbose_name_plural = "Journaux d'audit"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['category', 'timestamp']),
            models.Index(fields=['result', 'severity']),
        ]
    
    def __str__(self):
        return f"{self.username} - {self.action} - {self.timestamp}"
    
    def save(self, *args, **kwargs):
        """Override pour calculer le checksum"""
        if not self.checksum:
            self.checksum = self.calculate_checksum()
        super().save(*args, **kwargs)
    
    def calculate_checksum(self):
        """Calcule la somme de contrôle pour l'intégrité"""
        data = f"{self.username}:{self.action}:{self.resource}:{self.timestamp}:{self.result}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def verify_integrity(self):
        """Vérifie l'intégrité de l'entrée d'audit"""
        return self.checksum == self.calculate_checksum()
    
    @classmethod
    def log_action(cls, user, action, resource, request=None, **kwargs):
        """Méthode utilitaire pour créer une entrée d'audit"""
        # Extraire les informations de la requête
        user_ip = '127.0.0.1'
        user_agent = 'Unknown'
        session_key = ''
        
        if request:
            user_ip = cls.get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')[:500]
            session_key = request.session.session_key or ''
        
        return cls.objects.create(
            user=user,
            username=user.username if user else 'Anonymous',
            user_ip=user_ip,
            user_agent=user_agent,
            session_key=session_key,
            action=action,
            resource=resource,
            **kwargs
        )
    
    @staticmethod
    def get_client_ip(request):
        """Extrait l'IP réelle du client"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecurityEvent(models.Model):
    """
    Événements de sécurité spécifiques
    Exigence: Monitoring de sécurité et détection d'incidents
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Type d'événement de sécurité
    EVENT_TYPES = [
        ('failed_login', 'Tentative de connexion échouée'),
        ('account_lockout', 'Verrouillage de compte'),
        ('suspicious_activity', 'Activité suspecte'),
        ('unauthorized_access', 'Tentative d\'accès non autorisé'),
        ('privilege_escalation', 'Tentative d\'élévation de privilèges'),
        ('data_breach_attempt', 'Tentative de violation de données'),
        ('multiple_votes', 'Tentative de vote multiple'),
        ('vote_tampering', 'Tentative de falsification de vote'),
        ('system_intrusion', 'Tentative d\'intrusion système'),
    ]
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    
    # Détails de l'événement
    title = models.CharField(max_length=200)
    description = models.TextField()
    
    # Source de l'événement
    source_ip = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Timing
    detected_at = models.DateTimeField(auto_now_add=True)
    first_occurrence = models.DateTimeField(null=True, blank=True)
    last_occurrence = models.DateTimeField(null=True, blank=True)
    occurrence_count = models.PositiveIntegerField(default=1)
    
    # Gravité et statut
    SEVERITY_CHOICES = [
        ('info', 'Information'),
        ('low', 'Faible'),
        ('medium', 'Moyen'),
        ('high', 'Élevé'),
        ('critical', 'Critique'),
    ]
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    
    STATUS_CHOICES = [
        ('new', 'Nouveau'),
        ('investigating', 'En investigation'),
        ('confirmed', 'Confirmé'),
        ('false_positive', 'Faux positif'),
        ('resolved', 'Résolu'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    
    # Métadonnées
    raw_data = models.JSONField(default=dict, verbose_name="Données brutes")
    tags = models.JSONField(default=list, verbose_name="Tags")
    
    # Investigation
    investigated_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='investigated_events'
    )
    investigation_notes = models.TextField(blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = "Événement de sécurité"
        verbose_name_plural = "Événements de sécurité"
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['event_type', 'detected_at']),
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['source_ip', 'detected_at']),
        ]
    
    def __str__(self):
        return f"{self.event_type} - {self.severity} - {self.detected_at}"
    
    @classmethod
    def create_event(cls, event_type, title, description, request=None, user=None, **kwargs):
        """Crée un événement de sécurité"""
        source_ip = '127.0.0.1'
        user_agent = 'Unknown'
        
        if request:
            source_ip = AuditLog.get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')[:500]
        
        return cls.objects.create(
            event_type=event_type,
            title=title,
            description=description,
            source_ip=source_ip,
            user_agent=user_agent,
            user=user,
            **kwargs
        )


class VoteAudit(models.Model):
    """
    Audit spécifique aux votes pour traçabilité électorale
    Exigence: Traçabilité complète du processus de vote
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Référence à l'élection (toujours présente)
    election_id = models.UUIDField(verbose_name="ID de l'élection")
    election_title = models.CharField(max_length=200, verbose_name="Titre de l'élection")
    
    # Voter (anonymisé après vote)
    voter_id = models.UUIDField(null=True, blank=True, verbose_name="ID de l'électeur")
    voter_hash = models.CharField(max_length=64, verbose_name="Hash de l'électeur")
    
    # Vote tracking
    vote_token = models.CharField(max_length=64, unique=True, verbose_name="Token de vote")
    
    # Actions de vote
    VOTE_ACTIONS = [
        ('access_ballot', 'Accès au bulletin'),
        ('vote_cast', 'Vote émis'),
        ('vote_verified', 'Vote vérifié'),
        ('vote_counted', 'Vote comptabilisé'),
        ('vote_invalidated', 'Vote invalidé'),
    ]
    action = models.CharField(max_length=30, choices=VOTE_ACTIONS)
    
    # Timing précis
    timestamp = models.DateTimeField(auto_now_add=True)
    processing_time_ms = models.PositiveIntegerField(verbose_name="Temps de traitement (ms)")
    
    # Métadonnées techniques
    ip_hash = models.CharField(max_length=64, verbose_name="Hash IP")
    user_agent_hash = models.CharField(max_length=64, verbose_name="Hash User Agent")
    
    # Vérification cryptographique
    signature_valid = models.BooleanField(default=True)
    encryption_method = models.CharField(max_length=50, default='RSA-2048')
    
    # Résultat
    success = models.BooleanField(default=True)
    error_code = models.CharField(max_length=50, blank=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        verbose_name = "Audit de vote"
        verbose_name_plural = "Audits de votes"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['election_id', 'timestamp']),
            models.Index(fields=['vote_token', 'action']),
            models.Index(fields=['voter_hash', 'timestamp']),
        ]
    
    def __str__(self):
        return f"Vote Audit {self.vote_token[:8]} - {self.action}"
    
    @classmethod
    def log_vote_action(cls, election, action, vote_token, voter=None, **kwargs):
        """Log une action de vote"""
        # Anonymiser les données sensibles
        voter_hash = ''
        if voter:
            voter_hash = hashlib.sha256(f"{voter.id}:{election.id}".encode()).hexdigest()
        
        return cls.objects.create(
            election_id=election.id,
            election_title=election.title,
            voter_hash=voter_hash,
            vote_token=vote_token,
            action=action,
            **kwargs
        )


class SystemHealthLog(models.Model):
    """
    Journal de santé du système pour monitoring
    Exigence: Disponibilité et monitoring système
    """
    
    # Métrics système
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Performance
    response_time_ms = models.PositiveIntegerField(verbose_name="Temps de réponse (ms)")
    memory_usage_mb = models.PositiveIntegerField(verbose_name="Usage mémoire (MB)")
    cpu_usage_percent = models.DecimalField(max_digits=5, decimal_places=2)
    
    # Base de données
    db_connections = models.PositiveIntegerField(verbose_name="Connexions DB")
    db_response_time_ms = models.PositiveIntegerField(verbose_name="Temps réponse DB (ms)")
    
    # Sessions actives
    active_sessions = models.PositiveIntegerField(verbose_name="Sessions actives")
    active_votes = models.PositiveIntegerField(default=0, verbose_name="Votes en cours")
    
    # Statut global
    STATUS_CHOICES = [
        ('healthy', 'Sain'),
        ('warning', 'Avertissement'),
        ('critical', 'Critique'),
        ('down', 'Hors service'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='healthy')
    
    # Alertes
    alerts = models.JSONField(default=list, verbose_name="Alertes")
    
    class Meta:
        verbose_name = "Journal de santé système"
        verbose_name_plural = "Journaux de santé système"
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"System Health {self.timestamp} - {self.status}"


class ComplianceReport(models.Model):
    """
    Rapports de conformité pour audit externe
    Exigence: Conformité réglementaire et reporting
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Période du rapport
    report_period_start = models.DateTimeField()
    report_period_end = models.DateTimeField()
    
    # Type de rapport
    REPORT_TYPES = [
        ('security_audit', 'Audit de sécurité'),
        ('election_integrity', 'Intégrité électorale'),
        ('data_protection', 'Protection des données'),
        ('access_control', 'Contrôle d\'accès'),
        ('system_availability', 'Disponibilité système'),
    ]
    report_type = models.CharField(max_length=30, choices=REPORT_TYPES)
    
    # Métadonnées du rapport
    title = models.CharField(max_length=200)
    description = models.TextField()
    generated_by = models.ForeignKey(User, on_delete=models.PROTECT)
    generated_at = models.DateTimeField(auto_now_add=True)
    
    # Contenu du rapport (chiffré)
    encrypted_content = models.TextField(verbose_name="Contenu chiffré")
    content_hash = models.CharField(max_length=64, verbose_name="Hash du contenu")
    
    # Statistiques publiques
    total_events = models.PositiveIntegerField(default=0)
    security_events = models.PositiveIntegerField(default=0)
    failed_authentications = models.PositiveIntegerField(default=0)
    successful_votes = models.PositiveIntegerField(default=0)
    
    # Statut de conformité
    COMPLIANCE_STATUS = [
        ('compliant', 'Conforme'),
        ('non_compliant', 'Non conforme'),
        ('partially_compliant', 'Partiellement conforme'),
        ('under_review', 'En révision'),
    ]
    compliance_status = models.CharField(max_length=30, choices=COMPLIANCE_STATUS)
    
    # Recommandations
    recommendations = models.JSONField(default=list)
    
    class Meta:
        verbose_name = "Rapport de conformité"
        verbose_name_plural = "Rapports de conformité"
        ordering = ['-generated_at']
    
    def __str__(self):
        return f"{self.report_type} - {self.report_period_start.date()}"