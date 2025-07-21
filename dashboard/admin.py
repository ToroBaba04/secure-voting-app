# dashboard/admin.py - Interface d'administration pour les tableaux de bord
"""
Configuration de l'interface d'administration Django pour les tableaux de bord
Exigence: Interface d'administration pour les dashboards
"""

from django.contrib import admin

from .models import Dashboard, DashboardWidget, DashboardWidgetConfig, SystemMetric, Alert


@admin.register(Dashboard)
class DashboardAdmin(admin.ModelAdmin):
    """Administration pour les tableaux de bord"""
    
    list_display = ('name', 'owner', 'is_shared', 'is_active', 'view_count', 'created_at')
    list_filter = ('is_shared', 'is_active', 'is_default', 'theme', 'created_at')
    search_fields = ('name', 'description', 'owner__username')
    
    fieldsets = (
        ('Informations', {
            'fields': ('name', 'description', 'owner')
        }),
        ('Partage', {
            'fields': ('is_shared', 'shared_with_roles', 'shared_with_users')
        }),
        ('Configuration', {
            'fields': ('theme', 'refresh_interval', 'layout_config')
        }),
        ('Statut', {
            'fields': ('is_active', 'is_default', 'is_system_dashboard')
        }),
        ('Statistiques', {
            'fields': ('view_count', 'last_viewed'),
            'classes': ('collapse',)
        }),
    )


@admin.register(DashboardWidget)
class DashboardWidgetAdmin(admin.ModelAdmin):
    """Administration pour les widgets"""
    
    list_display = ('title', 'widget_type', 'category', 'is_active', 'created_at')
    list_filter = ('widget_type', 'category', 'is_active', 'created_at')
    search_fields = ('title', 'description')


@admin.register(SystemMetric)
class SystemMetricAdmin(admin.ModelAdmin):
    """Administration pour les métriques système"""
    
    list_display = ('timestamp', 'metric_name', 'value', 'unit')
    list_filter = ('metric_name', 'unit', 'timestamp')
    readonly_fields = ('timestamp',)
    
    def has_add_permission(self, request):
        return False


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    """Administration pour les alertes"""
    
    list_display = ('created_at', 'alert_type', 'title', 'severity', 'status', 'occurrence_count')
    list_filter = ('alert_type', 'severity', 'status', 'created_at')
    search_fields = ('title', 'message')
    
    fieldsets = (
        ('Alerte', {
            'fields': ('alert_type', 'title', 'message', 'severity')
        }),
        ('Statut', {
            'fields': ('status', 'acknowledged_by', 'resolved_by')
        }),
        ('Occurrences', {
            'fields': ('occurrence_count', 'last_occurrence')
        }),
        ('Données', {
            'fields': ('source_system', 'metadata'),
            'classes': ('collapse',)
        }),
    )

