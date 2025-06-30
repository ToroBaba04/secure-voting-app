# audit/urls.py - URLs pour l'interface d'audit de GalSecVote
"""
Configuration des URLs pour le système d'audit et de monitoring
Exigence: Routes sécurisées pour l'interface d'audit
"""

from django.urls import path
from . import views

app_name = 'audit'

# URLs principales d'audit
urlpatterns = [
    # Tableau de bord principal
    path('', views.AuditDashboardView.as_view(), name='dashboard'),
    
    # Consultation des logs
    path('logs/', views.AuditLogListView.as_view(), name='audit_logs'),
    path('logs/search/', views.search_audit_logs, name='search_logs'),
    path('logs/export/', views.export_audit_logs, name='export_logs'),
    
    # Événements de sécurité
    path('security/', views.SecurityEventListView.as_view(), name='security_events'),
    path('security/<uuid:pk>/', views.SecurityEventDetailView.as_view(), name='security_event_detail'),
    
    # Audits de vote
    path('votes/', views.VoteAuditListView.as_view(), name='vote_audits'),
    
    # Monitoring temps réel
    path('live/', views.live_monitoring, name='live_monitoring'),
    
    # Gestion des alertes
    path('alerts/', views.manage_alerts, name='manage_alerts'),
    path('alerts/<int:alert_id>/action/', views.alert_action, name='alert_action'),
    
    # Santé système
    path('system/', views.system_health_dashboard, name='system_health'),
    
    # Conformité
    path('compliance/', views.compliance_dashboard, name='compliance'),
    
    # Rapports
    path('reports/', views.AuditReportsView.as_view(), name='reports'),
]

# APIs pour AJAX et monitoring temps réel
api_patterns = [
    path('api/metrics/', views.audit_metrics_api, name='api_metrics'),
    path('api/alerts/', views.security_alerts_api, name='api_alerts'),
    path('api/status/', views.system_status_api, name='api_status'),
]

# Ajouter les APIs
urlpatterns += api_patterns