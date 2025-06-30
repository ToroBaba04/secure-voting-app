# audit/middleware.py - Middleware d'audit pour GalSecVote
"""
Middleware pour la journalisation automatique des événements de sécurité
Implémentation des exigences d'audit et de traçabilité
"""

import time
import json
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.urls import resolve
from django.utils import timezone
from django.conf import settings
import logging

User = get_user_model()
logger = logging.getLogger('audit')


class AuditMiddleware(MiddlewareMixin):
    """
    Middleware d'audit pour journaliser les actions critiques
    Exigence: Audit complet des actions utilisateur
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """Traite la requête entrante pour l'audit"""
        # Marquer le début du traitement
        request._audit_start_time = time.time()
        
        # Extraire les informations de base
        request._audit_data = {
            'ip_address': self.get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
            'method': request.method,
            'path': request.path,
            'timestamp': timezone.now(),
            'session_key': getattr(request.session, 'session_key', ''),
        }
        
        return None
    
    def process_response(self, request, response):
        """Traite la réponse pour finaliser l'audit"""
        # Calculer le temps de traitement
        if hasattr(request, '_audit_start_time'):
            processing_time = int((time.time() - request._audit_start_time) * 1000)
        else:
            processing_time = 0
        
        # Déterminer si cette requête doit être auditée
        if self.should_audit_request(request, response):
            self.log_request(request, response, processing_time)
        
        return response
    
    def should_audit_request(self, request, response):
        """Détermine si la requête doit être auditée"""
        # URLs à toujours auditer
        audit_paths = [
            '/accounts/login/',
            '/accounts/logout/',
            '/accounts/2fa/',
            '/vote/',
            '/admin/',
            '/api/',
        ]
        
        # Méthodes sensibles
        sensitive_methods = ['POST', 'PUT', 'PATCH', 'DELETE']
        
        # Statuts d'erreur
        error_status = response.status_code >= 400
        
        # Vérifier si l'URL correspond aux patterns d'audit
        path_match = any(request.path.startswith(path) for path in audit_paths)
        
        # Auditer si :
        # - URL sensible OU
        # - Méthode sensible OU  
        # - Erreur HTTP OU
        # - Utilisateur authentifié faisant une action
        return (
            path_match or 
            request.method in sensitive_methods or
            error_status or
            (request.user.is_authenticated and request.method != 'GET')
        )
    
    def log_request(self, request, response, processing_time):
        """Enregistre la requête dans les logs d'audit"""
        try:
            # Importer ici pour éviter les imports circulaires
            from .models import AuditLog
            
            # Déterminer l'action
            action = self.get_action_from_request(request)
            
            # Déterminer la ressource
            resource = self.get_resource_from_request(request)
            
            # Déterminer le résultat
            result = 'success' if response.status_code < 400 else 'failure'
            
            # Déterminer la sévérité
            severity = self.get_severity(request, response)
            
            # Déterminer la catégorie
            category = self.get_category(request)
            
            # Créer l'entrée d'audit
            AuditLog.log_action(
                user=request.user if request.user.is_authenticated else None,
                action=action,
                resource=resource,
                request=request,
                result=result,
                severity=severity,
                category=category,
                details={
                    'method': request.method,
                    'path': request.path,
                    'status_code': response.status_code,
                    'processing_time_ms': processing_time,
                    'content_length': len(response.content) if hasattr(response, 'content') else 0,
                }
            )
            
        except Exception as e:
            # En cas d'erreur dans l'audit, logger mais ne pas faire planter l'app
            logger.error(f"Erreur dans l'audit middleware: {e}")
    
    def get_action_from_request(self, request):
        """Détermine l'action basée sur la requête"""
        try:
            resolver_match = resolve(request.path)
            view_name = resolver_match.view_name
            
            # Mapping des noms de vues vers des actions lisibles
            action_mapping = {
                'accounts:login': 'user_login',
                'accounts:logout': 'user_logout',
                'accounts:2fa_verify': '2fa_verification',
                'vote:cast_vote': 'cast_vote',
                'vote:view_results': 'view_results',
                'admin:index': 'admin_access',
            }
            
            return action_mapping.get(view_name, f"{request.method.lower()}_{resolver_match.url_name or 'unknown'}")
            
        except Exception:
            return f"{request.method.lower()}_request"
    
    def get_resource_from_request(self, request):
        """Détermine la ressource basée sur la requête"""
        path_parts = request.path.strip('/').split('/')
        
        if 'accounts' in path_parts:
            return 'user_account'
        elif 'vote' in path_parts:
            return 'voting_system'
        elif 'admin' in path_parts:
            return 'admin_panel'
        elif 'api' in path_parts:
            return 'api_endpoint'
        else:
            return 'web_resource'
    
    def get_severity(self, request, response):
        """Détermine la sévérité basée sur la requête et réponse"""
        if response.status_code >= 500:
            return 'critical'
        elif response.status_code >= 400:
            return 'high'
        elif request.path.startswith('/vote/'):
            return 'high'  # Les actions de vote sont toujours importantes
        elif request.path.startswith('/admin/'):
            return 'medium'
        else:
            return 'low'
    
    def get_category(self, request):
        """Détermine la catégorie d'audit"""
        if 'login' in request.path or 'logout' in request.path:
            return 'authentication'
        elif '2fa' in request.path:
            return 'authentication'
        elif 'vote' in request.path:
            return 'vote_event'
        elif 'admin' in request.path:
            return 'authorization'
        elif 'api' in request.path:
            return 'data_access'
        else:
            return 'system_event'
    
    @staticmethod
    def get_client_ip(request):
        """Extrait l'IP réelle du client"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware pour ajouter des headers de sécurité
    Exigence: Protection contre les attaques web communes
    """
    
    def process_response(self, request, response):
        """Ajoute les headers de sécurité à la réponse"""
        
        # Headers de sécurité configurables
        security_headers = getattr(settings, 'SECURITY_HEADERS', {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
        })
        
        # Ajouter les headers
        for header, value in security_headers.items():
            if header not in response:
                response[header] = value
        
        # Content Security Policy pour les pages HTML
        if response.get('Content-Type', '').startswith('text/html'):
            if 'Content-Security-Policy' not in response:
                csp = getattr(settings, 'CONTENT_SECURITY_POLICY', 
                    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
                response['Content-Security-Policy'] = csp
        
        return response


class RequestValidationMiddleware(MiddlewareMixin):
    """
    Middleware pour valider les requêtes entrantes
    Exigence: Protection contre les attaques par injection
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.suspicious_patterns = getattr(settings, 'SUSPICIOUS_PATTERNS', [
            r'<script',
            r'javascript:',
            r'union\s+select',
            r'drop\s+table',
            r'--',
            r'/\*.*\*/',
        ])
        super().__init__(get_response)
    
    def process_request(self, request):
        """Valide la requête entrante"""
        
        # Vérifier les patterns suspects dans les paramètres
        if self.contains_suspicious_content(request):
            logger.warning(f"Suspicious request detected from {AuditMiddleware.get_client_ip(request)}: {request.path}")
            
            # Enregistrer l'événement de sécurité
            self.log_security_event(request, 'suspicious_request', 'Suspicious patterns detected in request')
            
            # Optionnel: bloquer la requête
            if getattr(settings, 'BLOCK_SUSPICIOUS_REQUESTS', False):
                return HttpResponse('Request blocked for security reasons', status=403)
        
        return None
    
    def contains_suspicious_content(self, request):
        """Vérifie si la requête contient du contenu suspect"""
        import re
        
        # Vérifier dans les paramètres GET
        for key, value in request.GET.items():
            for pattern in self.suspicious_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return True
        
        # Vérifier dans les données POST (si c'est du texte)
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                if isinstance(value, str):
                    for pattern in self.suspicious_patterns:
                        if re.search(pattern, value, re.IGNORECASE):
                            return True
        
        return False
    
    def log_security_event(self, request, event_type, description):
        """Enregistre un événement de sécurité"""
        try:
            from .models import SecurityEvent
            
            SecurityEvent.create_event(
                event_type=event_type,
                title=f"Security Event: {event_type}",
                description=description,
                request=request,
                severity='medium'
            )
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")


class SessionSecurityMiddleware(MiddlewareMixin):
    """
    Middleware pour la sécurité des sessions
    Exigence: Gestion sécurisée des sessions utilisateur
    """
    
    def process_request(self, request):
        """Vérifie la sécurité de la session"""
        
        if request.user.is_authenticated:
            # Vérifier si la session est valide
            session_key = request.session.session_key
            
            try:
                from accounts.models import UserSession
                
                # Vérifier si la session existe en base
                user_session = UserSession.objects.filter(
                    user=request.user,
                    session_key=session_key,
                    is_active=True
                ).first()
                
                if user_session:
                    # Vérifier si la session a expiré
                    if user_session.is_expired():
                        user_session.invalidate()
                        request.session.flush()
                        logger.info(f"Session expired for user {request.user.username}")
                    else:
                        # Mettre à jour l'activité
                        user_session.last_activity = timezone.now()
                        user_session.save()
                
            except Exception as e:
                logger.error(f"Error in session security middleware: {e}")
        
        return None