"""
Modèles pour le tableau de bord administratif de GalSecVote
Implémentation des exigences de supervision et monitoring
"""

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator, MaxValueValidator
import json
import uuid
from datetime import timedelta

User = get_user_model()


class DashboardWidget(models.Model):
    """
    Widgets configurables du tableau de bord
    Exigence: Interface d'administration personnalisable
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Configuration du widget
    name = models.CharField(max_length=100, verbose_name="Nom du widget")
    title = models.CharField(max_length=200, verbose_name="Titre affiché")
    description = models.TextField(blank=True)
    
    # Type de widget
    WIDGET_TYPES = [
        ('metric', 'Métrique'),
        ('chart', 'Graphique'),
        ('table', 'Tableau'),
        ('alert', 'Alerte'),
        ('status', 'Statut'),
        ('timeline', 'Timeline'),
    ]
    widget_type = models.CharField(max_length=20, choices=WIDGET_TYPES)
    
    # Configuration spécifique
    config = models.JSONField(default=dict, verbose_name="Configuration")
    data_source = models.CharField(max_length=100, verbose_name="Source de données")
    refresh_interval = models.PositiveIntegerField(default=300, verbose_name="Intervalle de rafraîchissement (sec)")
    
    # Positionnement
    position_x = models.PositiveIntegerField(default=0)
    position_y = models.PositiveIntegerField(default=0)
    width = models.PositiveIntegerField(default=4, validators=[MinValueValidator(1), MaxValueValidator(12)])
    height = models.PositiveIntegerField(default=4, validators=[MinValueValidator(1), MaxValueValidator(12)])
    
    # Permissions
    required_permission = models.CharField(max_length=100, blank=True)
    visible_to_roles = models.JSONField(default=list, verbose_name="Visible aux rôles")
    
    # Métadonnées
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_widgets')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Statuts
    is_active = models.BooleanField(default=True)
    is_system_widget = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = "Widget de tableau de bord"
        verbose_name_plural = "Widgets de tableau de bord"
        ordering = ['position_y', 'position_x']
    
    def __str__(self):
        return f"{self.title} ({self.widget_type})"
    
    def can_user_view(self, user):
        """Vérifie si l'utilisateur peut voir ce widget"""
        if not self.is_active:
            return False
        
        if self.required_permission and not user.has_perm(self.required_permission):
            return False
        
        if self.visible_to_roles and user.role not in self.visible_to_roles:
            return False
        
        return True


class SystemMetric(models.Model):
    """
    Métriques système pour monitoring
    Exigence: Surveillance de la santé du système
    """
    
    # Identifiant de la métrique
    metric_name = models.CharField(max_length=100, verbose_name="Nom de la métrique")
    
    # Valeurs
    value = models.DecimalField(max_digits=15, decimal_places=4, verbose_name="Valeur")
    unit = models.CharField(max_length=20, blank=True, verbose_name="Unité")
    
    # Métadonnées
    timestamp = models.DateTimeField(auto_now_add=True)
    source = models.CharField(max_length=100, verbose_name="Source")
    
    # Catégorie
    METRIC_CATEGORIES = [
        ('performance', 'Performance'),
        ('security', 'Sécurité'),
        ('availability', 'Disponibilité'),
        ('usage', 'Utilisation'),
        ('business', 'Métier'),
    ]
    category = models.CharField(max_length=20, choices=METRIC_CATEGORIES)
    
    # Alertes
    threshold_warning = models.DecimalField(max_digits=15, decimal_places=4, null=True, blank=True)
    threshold_critical = models.DecimalField(max_digits=15, decimal_places=4, null=True, blank=True)
    
    # Tags pour filtering
    tags = models.JSONField(default=dict, verbose_name="Tags")
    
    class Meta:
        verbose_name = "Métrique système"
        verbose_name_plural = "Métriques système"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['metric_name', 'timestamp']),
            models.Index(fields=['category', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.metric_name}: {self.value} {self.unit}"
    
    def get_status(self):
        """Retourne le statut basé sur les seuils"""
        if self.threshold_critical and self.value >= self.threshold_critical:
            return 'critical'
        elif self.threshold_warning and self.value >= self.threshold_warning:
            return 'warning'
        else:
            return 'normal'
    
    @classmethod
    def record_metric(cls, metric_name, value, unit='', category='performance', **kwargs):
        """Enregistre une nouvelle métrique"""
        return cls.objects.create(
            metric_name=metric_name,
            value=value,
            unit=unit,
            category=category,
            **kwargs
        )


class Alert(models.Model):
    """
    Système d'alertes pour le monitoring
    Exigence: Notification des événements critiques
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Type d'alerte
    ALERT_TYPES = [
        ('security_breach', 'Violation de sécurité'),
        ('system_error', 'Erreur système'),
        ('performance_issue', 'Problème de performance'),
        ('vote_anomaly', 'Anomalie de vote'),
        ('authentication_failure', 'Échec d\'authentification'),
        ('data_integrity', 'Intégrité des données'),
        ('system_maintenance', 'Maintenance système'),
    ]
    alert_type = models.CharField(max_length=30, choices=ALERT_TYPES)
    
    # Contenu de l'alerte
    title = models.CharField(max_length=200, verbose_name="Titre")
    message = models.TextField(verbose_name="Message")
    
    # Gravité
    SEVERITY_LEVELS = [
        ('info', 'Information'),
        ('warning', 'Avertissement'),
        ('error', 'Erreur'),
        ('critical', 'Critique'),
    ]
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='warning')
    
    # Source de l'alerte
    source_system = models.CharField(max_length=100, verbose_name="Système source")
    source_details = models.JSONField(default=dict, verbose_name="Détails source")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    first_occurrence = models.DateTimeField(auto_now_add=True)
    last_occurrence = models.DateTimeField(auto_now=True)
    occurrence_count = models.PositiveIntegerField(default=1)
    
    # Statut de l'alerte
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('acknowledged', 'Acquittée'),
        ('resolved', 'Résolue'),
        ('suppressed', 'Supprimée'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    # Gestion
    acknowledged_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='acknowledged_alerts'
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='resolved_alerts'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(blank=True)
    
    # Notifications
    notifications_sent = models.JSONField(default=list, verbose_name="Notifications envoyées")
    
    class Meta:
        verbose_name = "Alerte"
        verbose_name_plural = "Alertes"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['alert_type', 'status']),
            models.Index(fields=['severity', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.alert_type} - {self.severity} - {self.title}"
    
    def acknowledge(self, user, notes=""):
        """Acquitte l'alerte"""
        self.status = 'acknowledged'
        self.acknowledged_by = user
        self.acknowledged_at = timezone.now()
        if notes:
            self.resolution_notes = notes
        self.save()
    
    def resolve(self, user, notes=""):
        """Résout l'alerte"""
        self.status = 'resolved'
        self.resolved_by = user
        self.resolved_at = timezone.now()
        self.resolution_notes = notes
        self.save()
    
    @classmethod
    def create_alert(cls, alert_type, title, message, severity='warning', **kwargs):
        """Crée une nouvelle alerte"""
        # Vérifier s'il y a déjà une alerte similaire active
        existing_alert = cls.objects.filter(
            alert_type=alert_type,
            title=title,
            status='active'
        ).first()
        
        if existing_alert:
            # Incrémenter le compteur d'occurrence
            existing_alert.occurrence_count += 1
            existing_alert.last_occurrence = timezone.now()
            existing_alert.save()
            return existing_alert
        else:
            # Créer une nouvelle alerte
            return cls.objects.create(
                alert_type=alert_type,
                title=title,
                message=message,
                severity=severity,
                **kwargs
            )


class UserActivity(models.Model):
    """
    Activité des utilisateurs pour le monitoring
    Exigence: Surveillance de l'activité utilisateur
    """
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='dashboard_activities')
    
    # Action
    action = models.CharField(max_length=100, verbose_name="Action")
    resource = models.CharField(max_length=100, verbose_name="Ressource")
    details = models.JSONField(default=dict, verbose_name="Détails")
    
    # Contexte
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    session_id = models.CharField(max_length=40, blank=True)
    
    # Timing
    timestamp = models.DateTimeField(auto_now_add=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True, verbose_name="Durée (ms)")
    
    # Résultat
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        verbose_name = "Activité utilisateur"
        verbose_name_plural = "Activités utilisateur"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp}"


class SystemStatus(models.Model):
    """
    Statut global du système
    Exigence: Vue d'ensemble de la santé du système
    """
    
    # Composants du système
    COMPONENT_CHOICES = [
        ('web_server', 'Serveur Web'),
        ('database', 'Base de données'),
        ('authentication', 'Authentification'),
        ('voting_system', 'Système de vote'),
        ('encryption', 'Chiffrement'),
        ('audit_system', 'Système d\'audit'),
    ]
    component = models.CharField(max_length=30, choices=COMPONENT_CHOICES, unique=True)
    
    # Statut
    STATUS_CHOICES = [
        ('operational', 'Opérationnel'),
        ('degraded', 'Dégradé'),
        ('partial_outage', 'Panne partielle'),
        ('major_outage', 'Panne majeure'),
        ('maintenance', 'Maintenance'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='operational')
    
    # Détails
    status_message = models.TextField(blank=True)
    last_check = models.DateTimeField(auto_now=True)
    next_check = models.DateTimeField(null=True, blank=True)
    
    # Métriques de santé
    uptime_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=100.00)
    response_time_ms = models.PositiveIntegerField(default=0)
    error_rate_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    
    # Historique
    last_incident = models.DateTimeField(null=True, blank=True)
    incidents_count_24h = models.PositiveIntegerField(default=0)
    incidents_count_7d = models.PositiveIntegerField(default=0)
    
    class Meta:
        verbose_name = "Statut système"
        verbose_name_plural = "Statuts système"
        ordering = ['component']
    
    def __str__(self):
        return f"{self.component}: {self.status}"
    
    def is_healthy(self):
        """Vérifie si le composant est en bonne santé"""
        return self.status == 'operational' and self.uptime_percentage >= 99.0
    
    def update_status(self, status, message="", **metrics):
        """Met à jour le statut du composant"""
        old_status = self.status
        self.status = status
        self.status_message = message
        
        # Mettre à jour les métriques si fournies
        for key, value in metrics.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        # Si le statut a changé, créer une alerte
        if old_status != status and status != 'operational':
            Alert.create_alert(
                alert_type='system_error',
                title=f"Changement de statut: {self.get_component_display()}",
                message=f"Le composant {self.get_component_display()} est passé de {old_status} à {status}. {message}",
                severity='warning' if status == 'degraded' else 'critical',
                source_system='system_monitor'
            )
        
        self.save()


class ReportTemplate(models.Model):
    """
    Templates pour la génération de rapports
    Exigence: Reporting et conformité
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Informations du template
    name = models.CharField(max_length=100, verbose_name="Nom du template")
    description = models.TextField(verbose_name="Description")
    
    # Type de rapport
    REPORT_TYPES = [
        ('security_audit', 'Audit de sécurité'),
        ('election_summary', 'Résumé d\'élection'),
        ('user_activity', 'Activité utilisateur'),
        ('system_health', 'Santé du système'),
        ('compliance', 'Conformité'),
        ('performance', 'Performance'),
    ]
    report_type = models.CharField(max_length=30, choices=REPORT_TYPES)
    
    # Configuration du template
    template_config = models.JSONField(default=dict, verbose_name="Configuration")
    query_parameters = models.JSONField(default=dict, verbose_name="Paramètres de requête")
    
    # Format de sortie
    OUTPUT_FORMATS = [
        ('html', 'HTML'),
        ('pdf', 'PDF'),
        ('excel', 'Excel'),
        ('csv', 'CSV'),
        ('json', 'JSON'),
    ]
    default_format = models.CharField(max_length=10, choices=OUTPUT_FORMATS, default='html')
    
    # Permissions et accès
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_templates')
    allowed_roles = models.JSONField(default=list, verbose_name="Rôles autorisés")
    required_permissions = models.JSONField(default=list, verbose_name="Permissions requises")
    
    # Métadonnées
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used = models.DateTimeField(null=True, blank=True)
    usage_count = models.PositiveIntegerField(default=0)
    
    # Statuts
    is_active = models.BooleanField(default=True)
    is_system_template = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = "Template de rapport"
        verbose_name_plural = "Templates de rapports"
        ordering = ['report_type', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.report_type})"
    
    def can_user_use(self, user):
        """Vérifie si l'utilisateur peut utiliser ce template"""
        if not self.is_active:
            return False
        
        # Vérifier les rôles
        if self.allowed_roles and user.role not in self.allowed_roles:
            return False
        
        # Vérifier les permissions
        for perm in self.required_permissions:
            if not user.has_perm(perm):
                return False
        
        return True
    
    def increment_usage(self):
        """Incrémente le compteur d'utilisation"""
        self.usage_count += 1
        self.last_used = timezone.now()
        self.save()


class GeneratedReport(models.Model):
    """
    Rapports générés et archivés
    Exigence: Historique et archivage des rapports
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Template utilisé
    template = models.ForeignKey(ReportTemplate, on_delete=models.CASCADE, related_name='generated_reports')
    template_name = models.CharField(max_length=100, verbose_name="Nom du template")  # Backup
    
    # Métadonnées de génération
    generated_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='generated_reports')
    generated_at = models.DateTimeField(auto_now_add=True)
    
    # Période du rapport
    report_period_start = models.DateTimeField(null=True, blank=True)
    report_period_end = models.DateTimeField(null=True, blank=True)
    
    # Paramètres utilisés
    parameters = models.JSONField(default=dict, verbose_name="Paramètres utilisés")
    
    # Contenu du rapport
    title = models.CharField(max_length=200, verbose_name="Titre du rapport")
    content = models.TextField(verbose_name="Contenu")
    format = models.CharField(max_length=10, verbose_name="Format")
    
    # Fichier généré
    file_path = models.CharField(max_length=500, blank=True, verbose_name="Chemin du fichier")
    file_size_bytes = models.PositiveIntegerField(default=0)
    file_hash = models.CharField(max_length=64, blank=True, verbose_name="Hash du fichier")
    
    # Statuts
    is_confidential = models.BooleanField(default=False)
    is_archived = models.BooleanField(default=False)
    archived_at = models.DateTimeField(null=True, blank=True)
    
    # Accès et partage
    access_count = models.PositiveIntegerField(default=0)
    last_accessed = models.DateTimeField(null=True, blank=True)
    shared_with = models.ManyToManyField(User, blank=True, related_name='shared_reports')
    
    class Meta:
        verbose_name = "Rapport généré"
        verbose_name_plural = "Rapports générés"
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['template', 'generated_at']),
            models.Index(fields=['generated_by', 'generated_at']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.generated_at.date()}"
    
    def can_user_access(self, user):
        """Vérifie si l'utilisateur peut accéder au rapport"""
        # Le générateur peut toujours accéder
        if self.generated_by == user:
            return True
        
        # Vérifier si partagé
        if self.shared_with.filter(id=user.id).exists():
            return True
        
        # Les admins peuvent accéder aux rapports non confidentiels
        if user.role == 'admin' and not self.is_confidential:
            return True
        
        return False
    
    def increment_access(self, user):
        """Incrémente le compteur d'accès"""
        self.access_count += 1
        self.last_accessed = timezone.now()
        self.save()
        
        # Log l'accès pour audit
        from audit.models import AuditLog
        AuditLog.log_action(
            user=user,
            action='report_access',
            resource='generated_report',
            details={'report_id': str(self.id), 'title': self.title}
        )


class Dashboard(models.Model):
    """
    Configuration personnalisée des tableaux de bord
    Exigence: Tableaux de bord personnalisables par utilisateur/rôle
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Informations du dashboard
    name = models.CharField(max_length=100, verbose_name="Nom du dashboard")
    description = models.TextField(blank=True)
    
    # Propriétaire et partage
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_dashboards')
    is_shared = models.BooleanField(default=False)
    shared_with_roles = models.JSONField(default=list, verbose_name="Partagé avec les rôles")
    shared_with_users = models.ManyToManyField(User, blank=True, related_name='shared_dashboards')
    
    # Configuration du layout
    layout_config = models.JSONField(default=dict, verbose_name="Configuration du layout")
    widgets = models.ManyToManyField(DashboardWidget, through='DashboardWidgetConfig')
    
    # Paramètres d'affichage
    refresh_interval = models.PositiveIntegerField(default=300, verbose_name="Intervalle de rafraîchissement (sec)")
    theme = models.CharField(max_length=20, default='light', choices=[('light', 'Clair'), ('dark', 'Sombre')])
    
    # Métadonnées
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_viewed = models.DateTimeField(null=True, blank=True)
    view_count = models.PositiveIntegerField(default=0)
    
    # Statuts
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)
    is_system_dashboard = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = "Tableau de bord"
        verbose_name_plural = "Tableaux de bord"
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} (par {self.owner.username})"
    
    def can_user_view(self, user):
        """Vérifie si l'utilisateur peut voir ce dashboard"""
        if not self.is_active:
            return False
        
        # Le propriétaire peut toujours voir
        if self.owner == user:
            return True
        
        # Vérifier le partage
        if self.is_shared:
            if user.role in self.shared_with_roles:
                return True
            if self.shared_with_users.filter(id=user.id).exists():
                return True
        
        return False
    
    def increment_view(self):
        """Incrémente le compteur de vues"""
        self.view_count += 1
        self.last_viewed = timezone.now()
        self.save()


class DashboardWidgetConfig(models.Model):
    """
    Configuration spécifique d'un widget dans un dashboard
    Table de liaison avec configuration personnalisée
    """
    
    dashboard = models.ForeignKey(Dashboard, on_delete=models.CASCADE)
    widget = models.ForeignKey(DashboardWidget, on_delete=models.CASCADE)
    
    # Position dans le dashboard
    position_x = models.PositiveIntegerField(default=0)
    position_y = models.PositiveIntegerField(default=0)
    width = models.PositiveIntegerField(default=4)
    height = models.PositiveIntegerField(default=4)
    
    # Configuration spécifique pour ce dashboard
    custom_config = models.JSONField(default=dict, verbose_name="Configuration personnalisée")
    custom_title = models.CharField(max_length=200, blank=True, verbose_name="Titre personnalisé")
    
    # Statuts
    is_visible = models.BooleanField(default=True)
    added_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['dashboard', 'widget']
        verbose_name = "Configuration de widget"
        verbose_name_plural = "Configurations de widgets"
    
    def __str__(self):
        return f"{self.widget.title} dans {self.dashboard.name}"


class NotificationSetting(models.Model):
    """
    Paramètres de notification pour les utilisateurs
    Exigence: Notifications personnalisables
    """
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='notification_settings')
    
    # Types de notifications
    email_alerts = models.BooleanField(default=True, verbose_name="Alertes par email")
    sms_alerts = models.BooleanField(default=False, verbose_name="Alertes par SMS")
    browser_notifications = models.BooleanField(default=True, verbose_name="Notifications navigateur")
    
    # Niveaux de sévérité
    notify_info = models.BooleanField(default=False, verbose_name="Notifier les infos")
    notify_warning = models.BooleanField(default=True, verbose_name="Notifier les avertissements")
    notify_error = models.BooleanField(default=True, verbose_name="Notifier les erreurs")
    notify_critical = models.BooleanField(default=True, verbose_name="Notifier les critiques")
    
    # Types d'événements
    notify_security_events = models.BooleanField(default=True, verbose_name="Événements de sécurité")
    notify_election_events = models.BooleanField(default=True, verbose_name="Événements d'élection")
    notify_system_events = models.BooleanField(default=False, verbose_name="Événements système")
    notify_vote_events = models.BooleanField(default=True, verbose_name="Événements de vote")
    
    # Paramètres avancés
    quiet_hours_start = models.TimeField(null=True, blank=True, verbose_name="Début heures silencieuses")
    quiet_hours_end = models.TimeField(null=True, blank=True, verbose_name="Fin heures silencieuses")
    max_notifications_per_hour = models.PositiveIntegerField(default=10, verbose_name="Max notifications/heure")
    
    # Contacts alternatifs
    alternative_email = models.EmailField(blank=True, verbose_name="Email alternatif")
    phone_number = models.CharField(max_length=20, blank=True, verbose_name="Numéro de téléphone")
    
    # Métadonnées
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Paramètres de notification"
        verbose_name_plural = "Paramètres de notifications"
    
    def __str__(self):
        return f"Notifications de {self.user.username}"
    
    def should_notify(self, alert_type, severity, current_time=None):
        """Détermine si l'utilisateur doit être notifié"""
        if current_time is None:
            current_time = timezone.now().time()
        
        # Vérifier les heures silencieuses
        if (self.quiet_hours_start and self.quiet_hours_end and 
            self.quiet_hours_start <= current_time <= self.quiet_hours_end):
            return False
        
        # Vérifier le niveau de sévérité
        severity_checks = {
            'info': self.notify_info,
            'warning': self.notify_warning,
            'error': self.notify_error,
            'critical': self.notify_critical,
        }
        
        if not severity_checks.get(severity, True):
            return False
        
        # Vérifier le type d'événement
        event_checks = {
            'security_event': self.notify_security_events,
            'election_event': self.notify_election_events,
            'system_event': self.notify_system_events,
            'vote_event': self.notify_vote_events,
        }
        
        return event_checks.get(alert_type, True)