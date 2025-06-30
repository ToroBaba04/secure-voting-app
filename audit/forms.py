# audit/forms.py - Formulaires pour le système d'audit de GalSecVote
"""
Formulaires pour l'interface d'audit et de monitoring
Exigence: Interface utilisateur pour la consultation et génération de rapports
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import datetime, timedelta
from .models import AuditLog, SecurityEvent, ComplianceReport, ReportTemplate
import logging

logger = logging.getLogger('audit')


class AuditLogFilterForm(forms.Form):
    """
    Formulaire de filtrage pour les journaux d'audit
    Exigence: Interface de recherche et filtrage des événements
    """
    
    # Période de recherche
    date_start = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'type': 'datetime-local',
            'class': 'form-control'
        }),
        label="Date de début"
    )
    
    date_end = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'type': 'datetime-local',
            'class': 'form-control'
        }),
        label="Date de fin"
    )
    
    # Filtres par catégorie
    category = forms.ChoiceField(
        required=False,
        choices=[('', 'Toutes les catégories')] + AuditLog.CATEGORY_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Catégorie"
    )
    
    # Filtres par sévérité
    severity = forms.ChoiceField(
        required=False,
        choices=[('', 'Toutes les sévérités')] + AuditLog.SEVERITY_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Sévérité"
    )
    
    # Filtres par résultat
    result = forms.ChoiceField(
        required=False,
        choices=[('', 'Tous les résultats')] + AuditLog.RESULT_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Résultat"
    )
    
    # Recherche textuelle
    search = forms.CharField(
        required=False,
        max_length=255,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Rechercher dans les détails...'
        }),
        label="Recherche"
    )
    
    # Filtre par utilisateur
    user = forms.CharField(
        required=False,
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nom d\'utilisateur'
        }),
        label="Utilisateur"
    )
    
    # Filtre par action
    action = forms.CharField(
        required=False,
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Type d\'action'
        }),
        label="Action"
    )
    
    # Filtre par adresse IP
    ip_address = forms.CharField(
        required=False,
        max_length=45,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Adresse IP'
        }),
        label="Adresse IP"
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Définir des valeurs par défaut pour les dates
        if not self.data.get('date_end'):
            self.fields['date_end'].initial = timezone.now()
        
        if not self.data.get('date_start'):
            # Par défaut, les 7 derniers jours
            self.fields['date_start'].initial = timezone.now() - timedelta(days=7)
    
    def clean(self):
        """Validation croisée des champs"""
        cleaned_data = super().clean()
        date_start = cleaned_data.get('date_start')
        date_end = cleaned_data.get('date_end')
        
        # Vérifier que la date de début est antérieure à la date de fin
        if date_start and date_end:
            if date_start >= date_end:
                raise ValidationError(
                    "La date de début doit être antérieure à la date de fin."
                )
            
            # Vérifier que la période n'est pas trop longue (max 1 an)
            if (date_end - date_start).days > 365:
                raise ValidationError(
                    "La période de recherche ne peut pas dépasser 1 an."
                )
        
        return cleaned_data


class SecurityEventFilterForm(forms.Form):
    """
    Formulaire de filtrage pour les événements de sécurité
    Exigence: Interface spécialisée pour les événements de sécurité
    """
    
    event_type = forms.ChoiceField(
        required=False,
        choices=[('', 'Tous les types')] + SecurityEvent.EVENT_TYPES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Type d'événement"
    )
    
    severity = forms.ChoiceField(
        required=False,
        choices=[('', 'Toutes les sévérités')] + SecurityEvent.SEVERITY_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Sévérité"
    )
    
    status = forms.ChoiceField(
        required=False,
        choices=[('', 'Tous les statuts')] + SecurityEvent.STATUS_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Statut"
    )
    
    date_range = forms.ChoiceField(
        required=False,
        choices=[
            ('1h', 'Dernière heure'),
            ('24h', 'Dernières 24h'),
            ('7d', '7 derniers jours'),
            ('30d', '30 derniers jours'),
            ('custom', 'Période personnalisée')
        ],
        initial='24h',
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Période"
    )


class ReportGenerationForm(forms.Form):
    """
    Formulaire de génération de rapports d'audit
    Exigence: Interface de génération de rapports personnalisés
    """
    
    REPORT_TYPES = [
        ('security_audit', 'Audit de sécurité'),
        ('election_summary', 'Résumé d\'élection'),
        ('user_activity', 'Activité utilisateur'),
        ('system_health', 'Santé du système'),
        ('compliance', 'Conformité réglementaire'),
        ('custom', 'Rapport personnalisé')
    ]
    
    FORMAT_CHOICES = [
        ('html', 'HTML'),
        ('pdf', 'PDF'),
        ('excel', 'Excel'),
        ('csv', 'CSV'),
        ('json', 'JSON')
    ]
    
    report_type = forms.ChoiceField(
        choices=REPORT_TYPES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Type de rapport"
    )
    
    title = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Titre du rapport'
        }),
        label="Titre"
    )
    
    start_date = forms.DateTimeField(
        widget=forms.DateTimeInput(attrs={
            'type': 'datetime-local',
            'class': 'form-control'
        }),
        label="Date de début"
    )
    
    end_date = forms.DateTimeField(
        widget=forms.DateTimeInput(attrs={
            'type': 'datetime-local',
            'class': 'form-control'
        }),
        label="Date de fin"
    )
    
    format = forms.ChoiceField(
        choices=FORMAT_CHOICES,
        initial='html',
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'}),
        label="Format de sortie"
    )
    
    # Options spécifiques aux élections
    election_id = forms.CharField(
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Élection"
    )
    
    # Options de personnalisation
    include_charts = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Inclure les graphiques"
    )
    
    include_details = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Inclure les détails techniques"
    )
    
    confidential = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Marquer comme confidentiel"
    )
    
    # Filtres additionnels pour rapports personnalisés
    categories = forms.MultipleChoiceField(
        required=False,
        choices=AuditLog.CATEGORY_CHOICES,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'form-check-input'}),
        label="Catégories à inclure"
    )
    
    severity_levels = forms.MultipleChoiceField(
        required=False,
        choices=AuditLog.SEVERITY_CHOICES,
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'form-check-input'}),
        label="Niveaux de sévérité"
    )
    
    def __init__(self, *args, **kwargs):
        # Extraire les élections disponibles du kwargs
        self.available_elections = kwargs.pop('available_elections', [])
        super().__init__(*args, **kwargs)
        
        # Configurer le champ élection
        if self.available_elections:
            choices = [('', 'Sélectionner une élection...')]
            choices.extend([(e.id, e.title) for e in self.available_elections])
            self.fields['election_id'].widget = forms.Select(
                choices=choices,
                attrs={'class': 'form-select'}
            )
        
        # Valeurs par défaut pour les dates
        now = timezone.now()
        self.fields['end_date'].initial = now
        self.fields['start_date'].initial = now - timedelta(days=30)
    
    def clean(self):
        """Validation du formulaire"""
        cleaned_data = super().clean()
        report_type = cleaned_data.get('report_type')
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        election_id = cleaned_data.get('election_id')
        
        # Validation des dates
        if start_date and end_date:
            if start_date >= end_date:
                raise ValidationError(
                    "La date de début doit être antérieure à la date de fin."
                )
            
            # Limiter la période à 1 an maximum
            if (end_date - start_date).days > 365:
                raise ValidationError(
                    "La période ne peut pas dépasser 1 an."
                )
        
        # Validation spécifique aux rapports d'élection
        if report_type == 'election_summary':
            if not election_id:
                raise ValidationError(
                    "Une élection doit être sélectionnée pour ce type de rapport."
                )
        
        return cleaned_data


class AlertManagementForm(forms.Form):
    """
    Formulaire de gestion des alertes de sécurité
    Exigence: Interface de gestion des alertes
    """
    
    ACTION_CHOICES = [
        ('acknowledge', 'Acquitter'),
        ('resolve', 'Résoudre'),
        ('suppress', 'Supprimer'),
        ('escalate', 'Escalader')
    ]
    
    action = forms.ChoiceField(
        choices=ACTION_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Action"
    )
    
    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Notes sur l\'action entreprise...'
        }),
        label="Notes"
    )
    
    notify_team = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Notifier l'équipe"
    )


class SystemHealthConfigForm(forms.Form):
    """
    Formulaire de configuration du monitoring système
    Exigence: Configuration des alertes et seuils
    """
    
    # Seuils d'alerte pour les métriques
    cpu_warning_threshold = forms.IntegerField(
        min_value=1,
        max_value=100,
        initial=80,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': '1',
            'max': '100'
        }),
        label="Seuil d'avertissement CPU (%)"
    )
    
    cpu_critical_threshold = forms.IntegerField(
        min_value=1,
        max_value=100,
        initial=95,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': '1',
            'max': '100'
        }),
        label="Seuil critique CPU (%)"
    )
    
    memory_warning_threshold = forms.IntegerField(
        min_value=1,
        max_value=100,
        initial=85,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': '1',
            'max': '100'
        }),
        label="Seuil d'avertissement mémoire (%)"
    )
    
    memory_critical_threshold = forms.IntegerField(
        min_value=1,
        max_value=100,
        initial=95,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': '1',
            'max': '100'
        }),
        label="Seuil critique mémoire (%)"
    )
    
    response_time_warning = forms.IntegerField(
        min_value=1,
        initial=1000,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': '1'
        }),
        label="Seuil d'avertissement temps de réponse (ms)"
    )
    
    response_time_critical = forms.IntegerField(
        min_value=1,
        initial=3000,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': '1'
        }),
        label="Seuil critique temps de réponse (ms)"
    )
    
    # Configuration des notifications
    enable_email_alerts = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Activer les alertes par email"
    )
    
    enable_sms_alerts = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Activer les alertes par SMS"
    )
    
    alert_recipients = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Adresses email séparées par des virgules'
        }),
        label="Destinataires des alertes"
    )
    
    def clean(self):
        """Validation des seuils"""
        cleaned_data = super().clean()
        
        # Vérifier que les seuils critiques sont supérieurs aux seuils d'avertissement
        cpu_warning = cleaned_data.get('cpu_warning_threshold')
        cpu_critical = cleaned_data.get('cpu_critical_threshold')
        
        if cpu_warning and cpu_critical:
            if cpu_critical <= cpu_warning:
                raise ValidationError(
                    "Le seuil critique CPU doit être supérieur au seuil d'avertissement."
                )
        
        memory_warning = cleaned_data.get('memory_warning_threshold')
        memory_critical = cleaned_data.get('memory_critical_threshold')
        
        if memory_warning and memory_critical:
            if memory_critical <= memory_warning:
                raise ValidationError(
                    "Le seuil critique mémoire doit être supérieur au seuil d'avertissement."
                )
        
        response_warning = cleaned_data.get('response_time_warning')
        response_critical = cleaned_data.get('response_time_critical')
        
        if response_warning and response_critical:
            if response_critical <= response_warning:
                raise ValidationError(
                    "Le seuil critique de temps de réponse doit être supérieur au seuil d'avertissement."
                )
        
        return cleaned_data


class AuditExportForm(forms.Form):
    """
    Formulaire d'export des données d'audit
    Exigence: Export des données pour analyse externe
    """
    
    EXPORT_FORMATS = [
        ('csv', 'CSV'),
        ('json', 'JSON'),
        ('excel', 'Excel'),
        ('xml', 'XML')
    ]
    
    export_format = forms.ChoiceField(
        choices=EXPORT_FORMATS,
        initial='csv',
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Format d'export"
    )
    
    include_sensitive_data = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Inclure les données sensibles"
    )
    
    anonymize_users = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Anonymiser les utilisateurs"
    )
    
    compress_output = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Compresser le fichier"
    )


class CustomDashboardForm(forms.Form):
    """
    Formulaire de personnalisation du tableau de bord
    Exigence: Interface personnalisable de monitoring
    """
    
    REFRESH_INTERVALS = [
        (30, '30 secondes'),
        (60, '1 minute'),
        (300, '5 minutes'),
        (600, '10 minutes'),
        (1800, '30 minutes')
    ]
    
    dashboard_name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nom du tableau de bord'
        }),
        label="Nom du tableau de bord"
    )
    
    refresh_interval = forms.ChoiceField(
        choices=REFRESH_INTERVALS,
        initial=300,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Intervalle de rafraîchissement"
    )
    
    show_security_metrics = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Afficher les métriques de sécurité"
    )
    
    show_system_health = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Afficher la santé du système"
    )
    
    show_user_activity = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Afficher l'activité utilisateur"
    )
    
    show_recent_alerts = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Afficher les alertes récentes"
    )
    
    max_alerts_display = forms.IntegerField(
        min_value=5,
        max_value=50,
        initial=10,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': '5',
            'max': '50'
        }),
        label="Nombre max d'alertes à afficher"
    )