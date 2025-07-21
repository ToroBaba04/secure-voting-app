# accounts/admin.py - Interface d'administration pour les comptes utilisateurs
"""
Configuration de l'interface d'administration Django pour les utilisateurs et l'authentification
Exigence: Interface d'administration sécurisée
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe

from .models import User, UserProfile, TwoFactorAuth, UserSession, PasswordHistory


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """Administration personnalisée pour le modèle User"""
    
    list_display = ('username', 'email', 'role', 'is_verified', 'is_2fa_enabled', 'is_active', 'date_joined')
    list_filter = ('role', 'is_verified', 'is_2fa_enabled', 'is_active', 'date_joined')
    search_fields = ('username', 'email')
    ordering = ('-date_joined',)
    
    fieldsets = UserAdmin.fieldsets + (
        ('Informations GalSecVote', {
            'fields': ('role', 'is_verified', 'is_2fa_enabled', 'phone_number')
        }),
        ('Sécurité', {
            'fields': ('failed_login_attempts', 'lockout_until', 'is_locked', 'last_seen')
        }),
    )
    
    readonly_fields = ('last_seen', 'date_joined', 'failed_login_attempts')
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('profile')


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Administration pour les profils utilisateur"""
    
    list_display = ('user', 'first_name', 'last_name', 'notification_email', 'created_at')
    list_filter = ('notification_email', 'notification_sms', 'created_at')
    search_fields = ('user__username', 'first_name', 'last_name')
    
    fieldsets = (
        ('Informations personnelles', {
            'fields': ('user', 'first_name', 'last_name', 'birth_date')
        }),
        ('Préférences', {
            'fields': ('notification_email', 'notification_sms', 'session_timeout_preference')
        }),
    )


@admin.register(TwoFactorAuth)
class TwoFactorAuthAdmin(admin.ModelAdmin):
    """Administration pour l'authentification 2FA"""
    
    list_display = ('user', 'is_verified', 'method', 'created_at', 'last_used')
    list_filter = ('is_verified', 'method', 'created_at')
    search_fields = ('user__username',)
    readonly_fields = ('secret_key', 'backup_tokens', 'created_at', 'last_used')
    
    fieldsets = (
        ('Utilisateur', {
            'fields': ('user',)
        }),
        ('Configuration 2FA', {
            'fields': ('method', 'is_verified', 'secret_key')
        }),
        ('Tokens de secours', {
            'fields': ('backup_tokens',)
        }),
        ('Métadonnées', {
            'fields': ('created_at', 'last_used')
        }),
    )


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """Administration pour les sessions utilisateur"""
    
    list_display = ('user', 'ip_address', 'is_active', 'created_at', 'expires_at')
    list_filter = ('is_active', 'created_at', 'expires_at')
    search_fields = ('user__username', 'ip_address')
    readonly_fields = ('session_key', 'created_at')
    
    fieldsets = (
        ('Session', {
            'fields': ('user', 'session_key', 'ip_address', 'user_agent')
        }),
        ('Statut', {
            'fields': ('is_active', 'created_at', 'last_activity', 'expires_at')
        }),
    )


@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    """Administration pour l'historique des mots de passe"""
    
    list_display = ('user', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('user__username',)
    readonly_fields = ('user', 'password_hash', 'created_at')

