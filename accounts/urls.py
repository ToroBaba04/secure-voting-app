# accounts/urls.py - URLs d'authentification pour GalSecVote
"""
Configuration des URLs pour l'authentification sécurisée
Exigence: Routes sécurisées pour l'authentification 2FA
"""

from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'accounts'

urlpatterns = [
    # Authentification
    path('login/', views.SecureLoginView.as_view(), name='login'),
    path('logout/', views.SecureLogoutView.as_view(), name='logout'),
    path('register/', views.UserRegistrationView.as_view(), name='register'),
    
    # Authentification à deux facteurs
    path('2fa/setup/', views.TwoFactorSetupView.as_view(), name='2fa_setup'),
    path('2fa/verify/', views.TwoFactorVerifyView.as_view(), name='2fa_verify'),
    path('2fa/backup-tokens/', views.BackupTokensView.as_view(), name='2fa_backup_tokens'),
    path('2fa/disable/', views.DisableTwoFactorView.as_view(), name='2fa_disable'),
    
    # Gestion du profil
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('profile/update/', views.ProfileUpdateView.as_view(), name='profile_update'),
    path('profile/change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    
    # Gestion des sessions
    path('session/revoke/<uuid:session_id>/', views.RevokeSessionView.as_view(), name='revoke_session'),
    
    # Réinitialisation de mot de passe
    path('password-reset/', views.PasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    
    # Audit personnel
    path('audit/download/', views.download_audit_log, name='download_audit_log'),
]