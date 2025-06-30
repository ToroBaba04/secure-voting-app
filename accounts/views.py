# accounts/views.py - Vues d'authentification 2FA pour GalSecVote
"""
Vues pour l'authentification sécurisée avec 2FA
Implémentation des exigences d'authentification forte et de contrôle d'accès
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.views.generic import FormView, TemplateView, View
from django.urls import reverse_lazy, reverse
from django.http import JsonResponse, HttpResponseRedirect
from django.utils import timezone
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
import pyotp
import qrcode
import io
import base64
import secrets
import logging

from .models import User, TwoFactorAuth, UserSession, UserProfile
from .forms import (
    SecureLoginForm, TwoFactorSetupForm, TwoFactorVerifyForm,
    SecureUserCreationForm, PasswordResetRequestForm, ProfileUpdateForm,
    ChangePasswordForm, DisableTwoFactorForm
)
from audit.models import AuditLog, SecurityEvent

logger = logging.getLogger('accounts')


class SecureLoginView(FormView):
    """
    Vue de connexion sécurisée (première étape)
    Exigence: Authentification par email/mot de passe
    """
    template_name = 'accounts/login.html'
    form_class = SecureLoginForm
    
    def dispatch(self, request, *args, **kwargs):
        # Rediriger si l'utilisateur est déjà connecté
        if request.user.is_authenticated:
            return redirect('dashboard:home')
        return super().dispatch(request, *args, **kwargs)
    
    def form_valid(self, form):
        user = form.get_user()
        
        # Enregistrer l'événement d'authentification
        AuditLog.log_action(
            user=user,
            action='first_factor_auth',
            resource='user_account',
            request=self.request,
            result='success',
            category='authentication'
        )
        
        # Vérifier si l'utilisateur a la 2FA activée
        try:
            two_factor = user.two_factor
            if two_factor.is_verified:
                # Rediriger vers la vérification 2FA
                self.request.session['pre_2fa_user_id'] = user.id
                self.request.session['pre_2fa_timestamp'] = timezone.now().timestamp()
                return redirect('accounts:2fa_verify')
            else:
                # 2FA non configurée, forcer la configuration
                messages.warning(self.request, "Vous devez configurer l'authentification à deux facteurs.")
                self.request.session['setup_2fa_user_id'] = user.id
                return redirect('accounts:2fa_setup')
        
        except TwoFactorAuth.DoesNotExist:
            # Première connexion, forcer la configuration 2FA
            messages.info(self.request, "Pour votre sécurité, vous devez configurer l'authentification à deux facteurs.")
            self.request.session['setup_2fa_user_id'] = user.id
            return redirect('accounts:2fa_setup')
    
    def form_invalid(self, form):
        # Enregistrer la tentative de connexion échouée
        username = form.cleaned_data.get('username', 'unknown')
        
        SecurityEvent.create_event(
            event_type='failed_login',
            title='Tentative de connexion échouée',
            description=f'Échec de connexion pour {username}',
            request=self.request,
            severity='medium'
        )
        
        return super().form_invalid(form)


class TwoFactorSetupView(FormView):
    """
    Vue de configuration de l'authentification à deux facteurs
    Exigence: Configuration 2FA obligatoire
    """
    template_name = 'accounts/2fa_setup.html'
    form_class = TwoFactorSetupForm
    
    def dispatch(self, request, *args, **kwargs):
        # Vérifier que l'utilisateur est en cours de configuration
        if 'setup_2fa_user_id' not in request.session:
            messages.error(request, "Session expirée. Veuillez vous reconnecter.")
            return redirect('accounts:login')
        
        try:
            self.user = User.objects.get(id=request.session['setup_2fa_user_id'])
        except User.DoesNotExist:
            messages.error(request, "Utilisateur invalide.")
            return redirect('accounts:login')
        
        return super().dispatch(request, *args, **kwargs)
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        
        # Générer ou récupérer le secret TOTP
        try:
            two_factor = self.user.two_factor
            if not two_factor.is_verified:
                # Régénérer un nouveau secret
                secret_key = two_factor.generate_secret()
            else:
                secret_key = two_factor.secret_key
        except TwoFactorAuth.DoesNotExist:
            # Créer une nouvelle configuration 2FA
            two_factor = TwoFactorAuth.objects.create(user=self.user)
            secret_key = two_factor.generate_secret()
        
        kwargs['user'] = self.user
        kwargs['secret_key'] = secret_key
        self.secret_key = secret_key
        
        return kwargs
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Générer le QR code
        totp = pyotp.TOTP(self.secret_key)
        provisioning_uri = totp.provisioning_uri(
            name=self.user.email,
            issuer_name="GalSecVote"
        )
        
        # Créer le QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        
        context.update({
            'user': self.user,
            'secret_key': self.secret_key,
            'qr_code_data': qr_code_data,
            'manual_entry_key': self.secret_key
        })
        
        return context
    
    def form_valid(self, form):
        # Activer la 2FA pour l'utilisateur
        try:
            two_factor = self.user.two_factor
            two_factor.is_verified = True
            
            # Générer des tokens de récupération
            backup_tokens = two_factor.generate_backup_tokens()
            two_factor.save()
            
            # Connecter l'utilisateur
            login(self.request, self.user)
            
            # Créer une session utilisateur
            self.create_user_session()
            
            # Nettoyer la session temporaire
            del self.request.session['setup_2fa_user_id']
            
            # Enregistrer l'événement
            AuditLog.log_action(
                user=self.user,
                action='2fa_setup_complete',
                resource='user_account',
                request=self.request,
                result='success',
                category='authentication'
            )
            
            messages.success(self.request, "Authentification à deux facteurs configurée avec succès!")
            
            # Stocker les tokens de récupération pour affichage
            self.request.session['backup_tokens'] = backup_tokens
            
            return redirect('accounts:2fa_backup_tokens')
            
        except Exception as e:
            logger.error(f"Erreur lors de la configuration 2FA pour {self.user.username}: {e}")
            messages.error(self.request, "Erreur lors de la configuration. Veuillez réessayer.")
            return self.form_invalid(form)
    
    def create_user_session(self):
        """Crée une session utilisateur sécurisée"""
        UserSession.objects.create(
            user=self.user,
            session_key=self.request.session.session_key,
            ip_address=self.get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')[:500],
            expires_at=timezone.now() + timezone.timedelta(seconds=settings.SESSION_COOKIE_AGE)
        )
    
    def get_client_ip(self):
        """Extrait l'IP réelle du client"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip


class TwoFactorVerifyView(FormView):
    """
    Vue de vérification du code 2FA
    Exigence: Vérification TOTP obligatoire
    """
    template_name = 'accounts/2fa_verify.html'
    form_class = TwoFactorVerifyForm
    
    def dispatch(self, request, *args, **kwargs):
        # Vérifier la session pré-2FA
        if 'pre_2fa_user_id' not in request.session:
            messages.error(request, "Session expirée. Veuillez vous reconnecter.")
            return redirect('accounts:login')
        
        # Vérifier le timeout de la session
        timestamp = request.session.get('pre_2fa_timestamp', 0)
        if timezone.now().timestamp() - timestamp > 300:  # 5 minutes
            del request.session['pre_2fa_user_id']
            del request.session['pre_2fa_timestamp']
            messages.error(request, "Session expirée. Veuillez vous reconnecter.")
            return redirect('accounts:login')
        
        try:
            self.user = User.objects.get(id=request.session['pre_2fa_user_id'])
        except User.DoesNotExist:
            messages.error(request, "Utilisateur invalide.")
            return redirect('accounts:login')
        
        return super().dispatch(request, *args, **kwargs)
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user'] = self.user
        return context
    
    def form_valid(self, form):
        # Connecter l'utilisateur
        login(self.request, self.user)
        
        # Créer une session utilisateur
        user_session = UserSession.objects.create(
            user=self.user,
            session_key=self.request.session.session_key,
            ip_address=self.get_client_ip(),
            user_agent=self.request.META.get('HTTP_USER_AGENT', '')[:500],
            expires_at=timezone.now() + timezone.timedelta(seconds=settings.SESSION_COOKIE_AGE)
        )
        
        # Nettoyer la session temporaire
        del self.request.session['pre_2fa_user_id']
        del self.request.session['pre_2fa_timestamp']
        
        # Mettre à jour la dernière activité
        self.user.last_seen = timezone.now()
        self.user.save()
        
        # Enregistrer l'événement
        AuditLog.log_action(
            user=self.user,
            action='2fa_verification_success',
            resource='user_account',
            request=self.request,
            result='success',
            category='authentication',
            details={'session_id': user_session.id}
        )
        
        messages.success(self.request, f"Bienvenue, {self.user.username}!")
        return redirect('dashboard:home')
    
    def form_invalid(self, form):
        # Enregistrer la tentative échouée
        AuditLog.log_action(
            user=self.user,
            action='2fa_verification_failed',
            resource='user_account',
            request=self.request,
            result='failure',
            category='authentication'
        )
        
        SecurityEvent.create_event(
            event_type='failed_login',
            title='Échec de vérification 2FA',
            description=f'Code 2FA invalide pour {self.user.username}',
            request=self.request,
            user=self.user,
            severity='medium'
        )
        
        return super().form_invalid(form)
    
    def get_client_ip(self):
        """Extrait l'IP réelle du client"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip


class BackupTokensView(LoginRequiredMixin, TemplateView):
    """
    Vue d'affichage des tokens de récupération
    Exigence: Tokens de récupération pour accès d'urgence
    """
    template_name = 'accounts/backup_tokens.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Récupérer les tokens depuis la session (affichage unique)
        backup_tokens = self.request.session.pop('backup_tokens', None)
        
        if not backup_tokens:
            messages.warning(self.request, "Les tokens de récupération ne sont affichés qu'une seule fois.")
            return redirect('accounts:profile')
        
        context['backup_tokens'] = backup_tokens
        return context


class ProfileView(LoginRequiredMixin, TemplateView):
    """
    Vue du profil utilisateur
    Exigence: Gestion du profil et des paramètres de sécurité
    """
    template_name = 'accounts/profile.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        try:
            two_factor = self.request.user.two_factor
            context['has_2fa'] = two_factor.is_verified
        except TwoFactorAuth.DoesNotExist:
            context['has_2fa'] = False
        
        # Récupérer les sessions actives
        active_sessions = UserSession.objects.filter(
            user=self.request.user,
            is_active=True,
            expires_at__gt=timezone.now()
        ).order_by('-last_activity')
        
        context['active_sessions'] = active_sessions
        context['current_session'] = self.request.session.session_key
        
        return context


class ProfileUpdateView(LoginRequiredMixin, FormView):
    """
    Vue de mise à jour du profil
    Exigence: Modification des informations personnelles
    """
    template_name = 'accounts/profile_update.html'
    form_class = ProfileUpdateForm
    success_url = reverse_lazy('accounts:profile')
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['instance'] = self.request.user
        return kwargs
    
    def form_valid(self, form):
        form.save()
        
        # Enregistrer l'événement
        AuditLog.log_action(
            user=self.request.user,
            action='profile_update',
            resource='user_profile',
            request=self.request,
            result='success',
            category='data_modification'
        )
        
        messages.success(self.request, "Profil mis à jour avec succès.")
        return super().form_valid(form)


class ChangePasswordView(LoginRequiredMixin, FormView):
    """
    Vue de changement de mot de passe
    Exigence: Changement sécurisé du mot de passe
    """
    template_name = 'accounts/change_password.html'
    form_class = ChangePasswordForm
    success_url = reverse_lazy('accounts:profile')
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
    
    def form_valid(self, form):
        form.save()
        
        # Enregistrer l'événement
        AuditLog.log_action(
            user=self.request.user,
            action='password_change',
            resource='user_account',
            request=self.request,
            result='success',
            category='authentication'
        )
        
        # Invalider toutes les autres sessions
        UserSession.objects.filter(
            user=self.request.user
        ).exclude(
            session_key=self.request.session.session_key
        ).update(is_active=False)
        
        messages.success(self.request, "Mot de passe changé avec succès. Vos autres sessions ont été déconnectées.")
        return super().form_valid(form)


class DisableTwoFactorView(LoginRequiredMixin, FormView):
    """
    Vue de désactivation de l'authentification à deux facteurs
    Exigence: Désactivation sécurisée du 2FA
    """
    template_name = 'accounts/disable_2fa.html'
    form_class = DisableTwoFactorForm
    success_url = reverse_lazy('accounts:profile')
    
    def dispatch(self, request, *args, **kwargs):
        # Vérifier que l'utilisateur a la 2FA activée
        try:
            two_factor = request.user.two_factor
            if not two_factor.is_verified:
                messages.info(request, "L'authentification à deux facteurs n'est pas activée.")
                return redirect('accounts:profile')
        except TwoFactorAuth.DoesNotExist:
            messages.info(request, "L'authentification à deux facteurs n'est pas configurée.")
            return redirect('accounts:profile')
        
        return super().dispatch(request, *args, **kwargs)
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
    
    def form_valid(self, form):
        # Désactiver la 2FA
        try:
            two_factor = self.request.user.two_factor
            two_factor.delete()
            
            # Enregistrer l'événement
            AuditLog.log_action(
                user=self.request.user,
                action='2fa_disabled',
                resource='user_account',
                request=self.request,
                result='success',
                category='authentication'
            )
            
            SecurityEvent.create_event(
                event_type='security_event',
                title='Authentification 2FA désactivée',
                description=f'L\'utilisateur {self.request.user.username} a désactivé son authentification à deux facteurs',
                request=self.request,
                user=self.request.user,
                severity='medium'
            )
            
            messages.warning(self.request, "Authentification à deux facteurs désactivée. Votre compte est moins sécurisé.")
            
        except Exception as e:
            logger.error(f"Erreur lors de la désactivation 2FA pour {self.request.user.username}: {e}")
            messages.error(self.request, "Erreur lors de la désactivation. Veuillez réessayer.")
            return self.form_invalid(form)
        
        return super().form_valid(form)


class UserRegistrationView(FormView):
    """
    Vue d'inscription des utilisateurs
    Exigence: Création de compte sécurisée
    """
    template_name = 'accounts/register.html'
    form_class = SecureUserCreationForm
    
    def dispatch(self, request, *args, **kwargs):
        # Rediriger si l'utilisateur est déjà connecté
        if request.user.is_authenticated:
            return redirect('dashboard:home')
        
        # Vérifier si l'inscription est autorisée
        if not getattr(settings, 'ALLOW_REGISTRATION', True):
            messages.error(request, "L'inscription n'est pas autorisée actuellement.")
            return redirect('accounts:login')
        
        return super().dispatch(request, *args, **kwargs)
    
    def form_valid(self, form):
        # Créer l'utilisateur
        user = form.save()
        
        # Créer le profil utilisateur
        UserProfile.objects.create(user=user)
        
        # Enregistrer l'événement
        AuditLog.log_action(
            user=user,
            action='user_registration',
            resource='user_account',
            request=self.request,
            result='success',
            category='authentication'
        )
        
        messages.success(
            self.request, 
            "Compte créé avec succès! Veuillez vous connecter et configurer l'authentification à deux facteurs."
        )
        
        return redirect('accounts:login')


class SecureLogoutView(View):
    """
    Vue de déconnexion sécurisée
    Exigence: Déconnexion avec nettoyage de session
    """
    
    def post(self, request):
        if request.user.is_authenticated:
            # Invalider la session utilisateur
            try:
                user_session = UserSession.objects.get(
                    user=request.user,
                    session_key=request.session.session_key
                )
                user_session.invalidate()
            except UserSession.DoesNotExist:
                pass
            
            # Enregistrer l'événement
            AuditLog.log_action(
                user=request.user,
                action='user_logout',
                resource='user_account',
                request=request,
                result='success',
                category='authentication'
            )
            
            username = request.user.username
            logout(request)
            
            messages.success(request, f"Déconnexion réussie. À bientôt {username}!")
        
        return redirect('accounts:login')
    
    def get(self, request):
        # Rediriger les requêtes GET vers POST pour la sécurité
        return redirect('accounts:login')


class RevokeSessionView(LoginRequiredMixin, View):
    """
    Vue de révocation d'une session utilisateur
    Exigence: Gestion des sessions actives
    """
    
    def post(self, request, session_id):
        try:
            user_session = UserSession.objects.get(
                id=session_id,
                user=request.user,
                is_active=True
            )
            
            # Ne pas permettre de révoquer la session actuelle
            if user_session.session_key == request.session.session_key:
                messages.error(request, "Vous ne pouvez pas révoquer votre session actuelle.")
                return redirect('accounts:profile')
            
            # Révoquer la session
            user_session.invalidate()
            
            # Enregistrer l'événement
            AuditLog.log_action(
                user=request.user,
                action='session_revoked',
                resource='user_session',
                request=request,
                result='success',
                category='authentication',
                details={'revoked_session_id': session_id}
            )
            
            messages.success(request, "Session révoquée avec succès.")
            
        except UserSession.DoesNotExist:
            messages.error(request, "Session introuvable.")
        
        return redirect('accounts:profile')


@login_required
def download_audit_log(request):
    """
    Vue de téléchargement du journal d'audit personnel
    Exigence: Accès aux données personnelles d'audit
    """
    from django.http import HttpResponse
    import csv
    
    # Vérifier les permissions
    if not request.user.has_perm('audit.can_view_audit_logs'):
        messages.error(request, "Vous n'avez pas l'autorisation d'accéder aux journaux d'audit.")
        return redirect('accounts:profile')
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="audit_log_{request.user.username}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Date', 'Action', 'Ressource', 'Résultat', 'IP', 'Détails'])
    
    # Récupérer les logs de l'utilisateur (derniers 30 jours)
    logs = AuditLog.objects.filter(
        user=request.user,
        timestamp__gte=timezone.now() - timezone.timedelta(days=30)
    ).order_by('-timestamp')
    
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.action,
            log.resource,
            log.result,
            log.user_ip,
            str(log.details)
        ])
    
    # Enregistrer l'événement
    AuditLog.log_action(
        user=request.user,
        action='audit_log_download',
        resource='audit_data',
        request=request,
        result='success',
        category='data_access'
    )
    
    return response


class PasswordResetView(FormView):
    """
    Vue de demande de réinitialisation de mot de passe
    Exigence: Réinitialisation sécurisée
    """
    template_name = 'accounts/password_reset.html'
    form_class = PasswordResetRequestForm
    success_url = reverse_lazy('accounts:password_reset_done')
    
    def form_valid(self, form):
        email = form.cleaned_data['email']
        
        try:
            user = User.objects.get(email=email)
            
            # TODO: Implémenter l'envoi d'email de réinitialisation
            # Pour le moment, on simule juste l'événement
            
            AuditLog.log_action(
                user=user,
                action='password_reset_requested',
                resource='user_account',
                request=self.request,
                result='success',
                category='authentication'
            )
            
        except User.DoesNotExist:
            # Ne pas révéler si l'email existe ou non
            pass
        
        return super().form_valid(form)


class PasswordResetDoneView(TemplateView):
    """
    Vue de confirmation de demande de réinitialisation
    """
    template_name = 'accounts/password_reset_done.html'