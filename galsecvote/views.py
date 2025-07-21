# galsecvote/views.py - Vues d'erreur personnalisées pour GalSecVote
"""
Gestionnaires d'erreurs personnalisés pour une expérience utilisateur sécurisée
Exigence: Gestion sécurisée des erreurs sans fuite d'information
"""

from django.shortcuts import render
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseNotFound, HttpResponseServerError
from django.views.decorators.csrf import requires_csrf_token
from django.views.decorators.cache import never_cache
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
import logging

logger = logging.getLogger('galsecvote')


class HomeView(TemplateView):
    """
    Vue d'accueil du système GalSecVote
    """
    template_name = 'base/home.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'GalSecVote - Système de vote électronique sécurisé'
        return context


@never_cache
@requires_csrf_token
def bad_request(request, exception=None):
    """
    Gestionnaire d'erreur 400 - Requête incorrecte
    """
    context = {
        'error_code': 400,
        'error_title': 'Requête incorrecte',
        'error_message': 'La requête que vous avez envoyée ne peut pas être traitée.',
        'user_message': 'Veuillez vérifier les données saisies et réessayer.',
        'show_contact': True
    }
    
    # Log de l'erreur pour l'audit
    logger.warning(f"Erreur 400 pour {request.user if request.user.is_authenticated else 'utilisateur anonyme'} sur {request.path}")
    
    return HttpResponseBadRequest(
        render(request, 'errors/error.html', context)
    )


@never_cache
@requires_csrf_token
def permission_denied(request, exception=None):
    """
    Gestionnaire d'erreur 403 - Accès refusé
    """
    context = {
        'error_code': 403,
        'error_title': 'Accès refusé',
        'error_message': 'Vous n\'avez pas les permissions nécessaires pour accéder à cette page.',
        'user_message': 'Si vous pensez qu\'il s\'agit d\'une erreur, contactez l\'administrateur.',
        'show_login': not request.user.is_authenticated,
        'show_contact': True
    }
    
    # Log de l'tentative d'accès non autorisé
    logger.warning(f"Tentative d'accès non autorisé par {request.user if request.user.is_authenticated else 'utilisateur anonyme'} sur {request.path}")
    
    return HttpResponseForbidden(
        render(request, 'errors/error.html', context)
    )


@never_cache
@requires_csrf_token
def page_not_found(request, exception=None):
    """
    Gestionnaire d'erreur 404 - Page non trouvée
    """
    context = {
        'error_code': 404,
        'error_title': 'Page non trouvée',
        'error_message': 'La page que vous recherchez n\'existe pas ou a été déplacée.',
        'user_message': 'Vérifiez l\'URL ou utilisez la navigation pour retourner à l\'accueil.',
        'show_home': True,
        'show_contact': True
    }
    
    # Log de la page non trouvée
    logger.info(f"Page non trouvée: {request.path} pour {request.user if request.user.is_authenticated else 'utilisateur anonyme'}")
    
    return HttpResponseNotFound(
        render(request, 'errors/error.html', context)
    )


@never_cache
@requires_csrf_token
def server_error(request, exception=None):
    """
    Gestionnaire d'erreur 500 - Erreur serveur
    """
    context = {
        'error_code': 500,
        'error_title': 'Erreur serveur',
        'error_message': 'Une erreur interne s\'est produite sur le serveur.',
        'user_message': 'Veuillez réessayer dans quelques instants. Si le problème persiste, contactez l\'administrateur.',
        'show_home': True,
        'show_contact': True
    }
    
    # Log de l'erreur serveur
    logger.error(f"Erreur serveur 500 sur {request.path} pour {request.user if request.user.is_authenticated else 'utilisateur anonyme'}")
    
    return HttpResponseServerError(
        render(request, 'errors/error.html', context)
    )