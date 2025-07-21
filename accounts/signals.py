# accounts/signals.py - Signaux pour l'application accounts de GalSecVote
"""
Signaux Django pour automatiser certaines actions liées aux utilisateurs
Exigence: Automatisation des tâches de gestion des utilisateurs et sécurité
"""

import logging
from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from .models import UserProfile, TwoFactorAuth, UserSession, SecurityEvent, LoginAttempt
from audit.models import AuditLog

logger = logging.getLogger('accounts.signals')

User = get_user_model()


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Créer automatiquement un profil utilisateur lors de la création d'un utilisateur
    Exigence: Profil automatique pour tous les utilisateurs
    """
    if created:
        try:
            # Créer le profil utilisateur
            UserProfile.objects.create(user=instance)
            
            # Assigner au groupe par défaut "Voters"
            voters_group, group_created = Group.objects.get_or_create(name='Voters')
            instance.groups.add(voters_group)
            
            # Log de création d'utilisateur
            AuditLog.log_action(
                user=instance,
                action='user_created',
                resource='user_account',
                result='success',
                category='user_management',
                details={
                    'username': instance.username,
                    'email': instance.email,
                    'is_staff': instance.is_staff
                }
            )
            
            # Envoyer email de bienvenue si configuré
            if getattr(settings, 'SEND_WELCOME_EMAIL', True):
                send_welcome_email(instance)
            
            logger.info(f"Profil créé pour l'utilisateur {instance.username}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la création du profil pour {instance.username}: {e}")


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Sauvegarder le profil utilisateur quand l'utilisateur est sauvegardé
    """
    try:
        if hasattr(instance, 'userprofile'):
            instance.userprofile.save()
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde du profil pour {instance.username}: {e}")


@receiver(pre_save, sender=User)
def track_password_change(sender, instance, **kwargs):
    """
    Suivre les changements de mot de passe
    Exigence: Traçabilité des changements de sécurité
    """
    if instance.pk:  # L'utilisateur existe déjà
        try:
            old_user = User.objects.get(pk=instance.pk)
            
            # Vérifier si le mot de passe a changé
            if old_user.password != instance.password:
                # Le mot de passe a été modifié
                if hasattr(instance, 'userprofile'):
                    instance.userprofile.last_password_change = timezone.now()
                
                # Log du changement de mot de passe
                AuditLog.log_action(
                    user=instance,
                    action='password_changed',
                    resource='authentication',
                    result='success',
                    category='security',
                    details={'username': instance.username}
                )
                
                # Créer un événement de sécurité
                SecurityEvent.log_event(
                    event_type='password_change',
                    user=instance,
                    severity='medium',
                    description=f"Mot de passe modifié pour l'utilisateur {instance.username}"
                )
                
                logger.info(f"Changement de mot de passe détecté pour {instance.username}")
                
        except User.DoesNotExist:
            # Nouvel utilisateur, pas de vérification nécessaire
            pass
        except Exception as e:
            logger.error(f"Erreur lors du suivi du changement de mot de passe: {e}")


@receiver(post_save, sender=TwoFactorAuth)
def track_2fa_changes(sender, instance, created, **kwargs):
    """
    Suivre les changements de configuration 2FA
    Exigence: Traçabilité des changements de sécurité
    """
    try:
        if created:
            action = '2fa_configured'
            description = f"2FA configuré pour {instance.user.username}"
        else:
            action = '2fa_enabled' if instance.is_enabled else '2fa_disabled'
            description = f"2FA {'activé' if instance.is_enabled else 'désactivé'} pour {instance.user.username}"
        
        # Log de l'action
        AuditLog.log_action(
            user=instance.user,
            action=action,
            resource='authentication',
            result='success',
            category='security',
            details={'username': instance.user.username}
        )
        
        # Créer un événement de sécurité
        SecurityEvent.log_event(
            event_type=action,
            user=instance.user,
            severity='medium',
            description=description
        )
        
        logger.info(f"Changement 2FA détecté: {description}")
        
    except Exception as e:
        logger.error(f"Erreur lors du suivi des changements 2FA: {e}")


@receiver(post_delete, sender=Session)
def end_user_session_on_delete(sender, instance, **kwargs):
    """
    Marquer la session utilisateur comme terminée quand la session Django est supprimée
    Exigence: Suivi précis des sessions
    """
    try:
        UserSession.end_session(instance.session_key)
        logger.debug(f"Session {instance.session_key} marquée comme terminée")
    except Exception as e:
        logger.error(f"Erreur lors de la fin de session: {e}")


@receiver(post_save, sender=LoginAttempt)
def monitor_failed_login_attempts(sender, instance, created, **kwargs):
    """
    Surveiller les tentatives de connexion échouées pour détecter les attaques
    Exigence: Détection des tentatives d'intrusion
    """
    if created and not instance.success:
        try:
            # Compter les échecs récents pour cet utilisateur
            recent_failures = LoginAttempt.objects.filter(
                username=instance.username,
                success=False,
                timestamp__gte=timezone.now() - timezone.timedelta(minutes=30)
            ).count()
            
            # Compter les échecs récents pour cette IP
            ip_failures = LoginAttempt.objects.filter(
                ip_address=instance.ip_address,
                success=False,
                timestamp__gte=timezone.now() - timezone.timedelta(minutes=30)
            ).count()
            
            # Seuils d'alerte
            if recent_failures >= 5:
                # Créer un événement de sécurité pour tentatives répétées sur un compte
                SecurityEvent.log_event(
                    event_type='login_locked',
                    severity='high',
                    description=f"Compte {instance.username} verrouillé après {recent_failures} tentatives échouées",
                    ip_address=instance.ip_address,
                    additional_data={
                        'username': instance.username,
                        'failure_count': recent_failures,
                        'time_window_minutes': 30
                    }
                )
                
                logger.warning(f"Compte {instance.username} verrouillé après {recent_failures} tentatives")
            
            if ip_failures >= 10:
                # Créer un événement de sécurité pour tentatives répétées depuis une IP
                SecurityEvent.log_event(
                    event_type='suspicious_activity',
                    severity='critical',
                    description=f"Activité suspecte détectée depuis l'IP {instance.ip_address}: {ip_failures} tentatives échouées",
                    ip_address=instance.ip_address,
                    additional_data={
                        'ip_address': instance.ip_address,
                        'failure_count': ip_failures,
                        'time_window_minutes': 30
                    }
                )
                
                logger.critical(f"Activité suspecte détectée depuis l'IP {instance.ip_address}")
        
        except Exception as e:
            logger.error(f"Erreur lors de la surveillance des tentatives de connexion: {e}")


@receiver(post_save, sender=User)
def notify_admin_new_user(sender, instance, created, **kwargs):
    """
    Notifier les administrateurs lors de la création d'un nouvel utilisateur
    Exigence: Notification des activités importantes
    """
    if created and getattr(settings, 'NOTIFY_ADMIN_NEW_USER', True):
        try:
            # Récupérer les emails des administrateurs
            admin_emails = User.objects.filter(
                is_staff=True,
                is_active=True,
                email__isnull=False
            ).exclude(email='').values_list('email', flat=True)
            
            if admin_emails:
                # Envoyer notification aux administrateurs
                subject = f"[GalSecVote] Nouvel utilisateur inscrit: {instance.username}"
                message = f"""
                Un nouvel utilisateur s'est inscrit sur GalSecVote:
                
                Nom d'utilisateur: {instance.username}
                Email: {instance.email}
                Nom complet: {instance.get_full_name()}
                Date d'inscription: {instance.date_joined}
                
                Veuillez vérifier et valider ce compte si nécessaire.
                """
                
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=list(admin_emails),
                    fail_silently=True
                )
                
                logger.info(f"Notification envoyée aux administrateurs pour le nouvel utilisateur {instance.username}")
        
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de notification admin: {e}")


def send_welcome_email(user):
    """
    Envoyer un email de bienvenue au nouvel utilisateur
    Exigence: Communication avec les utilisateurs
    """
    try:
        if user.email:
            subject = "Bienvenue sur GalSecVote"
            
            # Contexte pour le template
            context = {
                'user': user,
                'site_name': 'GalSecVote',
                'login_url': f"{settings.SITE_URL}/accounts/login/" if hasattr(settings, 'SITE_URL') else '/accounts/login/'
            }
            
            # Générer le contenu HTML et texte
            html_message = render_to_string('accounts/emails/welcome.html', context)
            plain_message = strip_tags(html_message)
            
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=True
            )
            
            logger.info(f"Email de bienvenue envoyé à {user.email}")
    
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de l'email de bienvenue: {e}")


# Signal personnalisé pour les événements de sécurité critiques
from django.dispatch import Signal

# Créer un signal personnalisé
security_alert = Signal()


@receiver(security_alert)
def handle_security_alert(sender, **kwargs):
    """
    Gestionnaire pour les alertes de sécurité critiques
    Exigence: Réponse automatique aux menaces de sécurité
    """
    try:
        event_type = kwargs.get('event_type')
        severity = kwargs.get('severity')
        description = kwargs.get('description')
        user = kwargs.get('user')
        ip_address = kwargs.get('ip_address')
        
        # Log de l'alerte
        logger.critical(f"Alerte de sécurité: {event_type} - {description}")
        
        # Créer l'événement de sécurité
        SecurityEvent.log_event(
            event_type=event_type,
            user=user,
            severity=severity,
            description=description,
            ip_address=ip_address
        )
        
        # Si c'est critique, notifier immédiatement les administrateurs
        if severity == 'critical':
            notify_admins_security_alert(event_type, description, user, ip_address)
    
    except Exception as e:
        logger.error(f"Erreur lors de la gestion de l'alerte de sécurité: {e}")


def notify_admins_security_alert(event_type, description, user=None, ip_address=None):
    """
    Notifier les administrateurs d'une alerte de sécurité critique
    """
    try:
        admin_emails = User.objects.filter(
            is_superuser=True,
            is_active=True,
            email__isnull=False
        ).exclude(email='').values_list('email', flat=True)
        
        if admin_emails:
            subject = f"[GalSecVote] ALERTE SÉCURITÉ CRITIQUE: {event_type}"
            message = f"""
            ALERTE SÉCURITÉ CRITIQUE détectée sur GalSecVote:
            
            Type d'événement: {event_type}
            Description: {description}
            Utilisateur concerné: {user.username if user else 'N/A'}
            Adresse IP: {ip_address or 'N/A'}
            Heure: {timezone.now()}
            
            Veuillez prendre les mesures appropriées immédiatement.
            """
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=list(admin_emails),
                fail_silently=False  # Ne pas échouer silencieusement pour les alertes critiques
            )
            
            logger.info(f"Alerte de sécurité critique envoyée aux administrateurs")
    
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de l'alerte de sécurité: {e}")