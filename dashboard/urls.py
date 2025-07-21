# dashboard/urls.py - URLs pour le tableau de bord de GalSecVote
"""
Configuration des URLs pour les tableaux de bord d'administration
Exigence: Interface d'administration et de monitoring
"""

from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    # Tableau de bord principal
    path('', views.DashboardHomeView.as_view(), name='home'),
    
    # Gestion des tableaux de bord personnalisés
    path('custom/', views.CustomDashboardListView.as_view(), name='custom_list'),
    path('custom/create/', views.CreateDashboardView.as_view(), name='create_dashboard'),
    path('custom/<uuid:pk>/', views.CustomDashboardDetailView.as_view(), name='custom_detail'),
    path('custom/<uuid:pk>/edit/', views.EditDashboardView.as_view(), name='edit_dashboard'),
    path('custom/<uuid:pk>/delete/', views.DeleteDashboardView.as_view(), name='delete_dashboard'),
    
    # Widgets
    path('widgets/', views.WidgetListView.as_view(), name='widget_list'),
    path('widgets/<int:pk>/', views.WidgetDetailView.as_view(), name='widget_detail'),
    
    # Métriques système
    path('metrics/', views.SystemMetricsView.as_view(), name='system_metrics'),
    path('metrics/export/', views.export_metrics, name='export_metrics'),
    
    # Alertes
    path('alerts/', views.AlertManagementView.as_view(), name='alert_management'),
    path('alerts/<int:pk>/acknowledge/', views.acknowledge_alert, name='acknowledge_alert'),
    path('alerts/<int:pk>/resolve/', views.resolve_alert, name='resolve_alert'),
    
    # Monitoring en temps réel
    path('live/', views.LiveMonitoringView.as_view(), name='live_monitoring'),
    
    # APIs pour AJAX
    path('api/metrics/', views.metrics_api, name='api_metrics'),
    path('api/alerts/', views.alerts_api, name='api_alerts'),
    path('api/system-status/', views.system_status_api, name='api_system_status'),
    path('api/dashboard/<uuid:dashboard_id>/data/', views.dashboard_data_api, name='api_dashboard_data'),
    
    # Configuration
    path('settings/', views.DashboardSettingsView.as_view(), name='settings'),
    path('settings/notifications/', views.NotificationSettingsView.as_view(), name='notification_settings'),
]