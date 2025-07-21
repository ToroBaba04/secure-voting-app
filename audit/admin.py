# audit/admin.py - Interface d'administration pour l'audit
"""
Configuration de l'interface d'administration Django pour l'audit
Exigence: Interface d'administration pour le monitoring
"""

from django.contrib import admin
from django.utils.html import format_html

from .models import AuditLog, SecurityEvent, VoteAudit, SystemHealthLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Administration pour les logs d'audit"""
    
    list_display = ('timestamp', 'user', 'action', 'resource', 'result', 'user_ip')
    list_filter = ('result', 'category', 'severity', 'timestamp')
    search_fields = ('user__username', 'action', 'resource', 'user_ip')
    readonly_fields = ('id', 'timestamp', 'session_key')
    
    fieldsets = (
        ('Utilisateur', {
            'fields': ('user', 'username', 'user_ip', 'user_agent', 'session_key')
        }),
        ('Action', {
            'fields': ('action', 'resource', 'details', 'old_values', 'new_values')
        }),
        ('Résultat', {
            'fields': ('result', 'error_message', 'category', 'severity')
        }),
        ('Métadonnées', {
            'fields': ('id', 'timestamp'),
            'classes': ('collapse',)
        }),
    )
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    """Administration pour les événements de sécurité"""
    
    list_display = ('detected_at', 'event_type', 'severity', 'status', 'source_ip')
    list_filter = ('event_type', 'severity', 'status', 'detected_at')
    search_fields = ('title', 'description', 'source_ip')
    
    fieldsets = (
        ('Événement', {
            'fields': ('event_type', 'title', 'description', 'severity')
        }),
        ('Source', {
            'fields': ('source_ip', 'user_agent', 'user')
        }),
        ('Traitement', {
            'fields': ('status', 'investigated_by', 'resolved_by', 'notes')
        }),
        ('Métadonnées', {
            'fields': ('detected_at', 'investigated_at', 'resolved_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(VoteAudit)
class VoteAuditAdmin(admin.ModelAdmin):
    """Administration pour l'audit des votes"""
    
    list_display = ('timestamp', 'election_title', 'action', 'success', 'vote_token_short')
    list_filter = ('action', 'success', 'timestamp')
    search_fields = ('election_title', 'vote_token')
    readonly_fields = ('id', 'timestamp', 'processing_time_ms')
    
    def vote_token_short(self, obj):
        return f"{obj.vote_token[:8]}..."
    vote_token_short.short_description = 'Token'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(SystemHealthLog)
class SystemHealthLogAdmin(admin.ModelAdmin):
    """Administration pour les logs de santé système"""
    
    list_display = ('timestamp', 'status', 'response_time_ms', 'memory_usage_mb', 'active_sessions')
    list_filter = ('status', 'timestamp')
    readonly_fields = ('timestamp',)
    
    def has_add_permission(self, request):
        return False
