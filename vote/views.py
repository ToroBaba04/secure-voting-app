# vote/views.py - Vues pour le système de vote sécurisé de GalSecVote
"""
Vues pour l'interface de vote sécurisée
Exigence: Interface utilisateur sécurisée pour le processus de vote
"""

import json
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib import messages
from django.views.generic import TemplateView, ListView, DetailView
from django.http import JsonResponse, HttpResponseForbidden, Http404
from django.urls import reverse_lazy, reverse
from django.utils import timezone
from django.db import transaction
from django.core.exceptions import PermissionDenied
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache

from .models import Election, Candidate, Vote, VoteRecord, ElectionResult
from .vote_processor import VoteProcessor, VoteValidator, VoteCounter
from .encryption import generate_election_keypair, validate_election_keys
from audit.models import AuditLog, SecurityEvent

logger = logging.getLogger('vote.views')


class ActiveElectionsView(LoginRequiredMixin, ListView):
    """
    Vue des élections actives pour l'électeur
    Exigence: Interface de sélection des élections disponibles
    """
    model = Election
    template_name = 'vote/elections_list.html'
    context_object_name = 'elections'
    paginate_by = 10
    
    def get_queryset(self):
        """Retourne les élections ouvertes et accessibles à l'utilisateur"""
        now = timezone.now()
        return Election.objects.filter(
            status='active',
            start_date__lte=now,
            end_date__gte=now,
            is_active=True,
            voters__user=self.request.user,
            voters__is_eligible=True
        ).distinct().order_by('-start_date')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Ajouter des informations sur les votes déjà effectués
        user_votes = VoteRecord.objects.filter(
            voter=self.request.user,
            election__in=context['elections']
        ).values_list('election_id', flat=True)
        
        context['user_votes'] = list(user_votes)
        context['has_available_elections'] = context['elections'].exists()
        
        return context


@method_decorator([csrf_protect, never_cache], name='dispatch')
class VotingView(LoginRequiredMixin, DetailView):
    """
    Vue principale pour l'interface de vote
    Exigence: Interface de vote sécurisée avec validation
    """
    model = Election
    template_name = 'vote/voting_interface.html'
    context_object_name = 'election'
    
    def dispatch(self, request, *args, **kwargs):
        """Vérifications de sécurité avant affichage"""
        election = self.get_object()
        
        # Vérifier l'éligibilité
        if not election.is_user_eligible(request.user):
            messages.error(request, "Vous n'êtes pas autorisé à voter dans cette élection.")
            return redirect('vote:elections_list')
        
        # Vérifier si déjà voté
        if election.has_user_voted(request.user):
            messages.info(request, "Vous avez déjà voté dans cette élection.")
            return redirect('vote:vote_confirmation', pk=election.pk)
        
        # Vérifier que l'élection est ouverte
        if not election.is_voting_open():
            messages.error(request, "Cette élection n'est pas ouverte au vote.")
            return redirect('vote:elections_list')
        
        return super().dispatch(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        election = self.get_object()
        
        # Candidats actifs
        context['candidates'] = election.candidates.filter(is_active=True).order_by('order', 'name')
        
        # Informations de sécurité
        context['voting_info'] = {
            'encryption_enabled': True,
            'anonymity_guaranteed': election.is_anonymous,
            'audit_enabled': True,
            'time_remaining': self._get_time_remaining(election),
        }
        
        # Enregistrer l'accès au bulletin
        AuditLog.log_action(
            user=self.request.user,
            action='ballot_access',
            resource='election_ballot',
            request=self.request,
            result='success',
            category='vote_event',
            details={
                'election_id': str(election.id),
                'election_title': election.title
            }
        )
        
        return context
    
    def _get_time_remaining(self, election):
        """Calcule le temps restant pour voter"""
        now = timezone.now()
        if election.end_date > now:
            remaining = election.end_date - now
            return {
                'days': remaining.days,
                'hours': remaining.seconds // 3600,
                'minutes': (remaining.seconds % 3600) // 60
            }
        return None
    
    def post(self, request, *args, **kwargs):
        """Traite la soumission du vote"""
        election = self.get_object()
        candidate_id = request.POST.get('candidate_id')
        
        if not candidate_id:
            messages.error(request, "Vous devez sélectionner un candidat.")
            return self.get(request, *args, **kwargs)
        
        try:
            # Vérifier que le candidat existe
            candidate = get_object_or_404(Candidate, id=candidate_id, election=election, is_active=True)
            
            # Confirmer avec l'utilisateur (si pas déjà confirmé)
            if not request.POST.get('confirmed'):
                return render(request, 'vote/vote_confirmation.html', {
                    'election': election,
                    'candidate': candidate,
                    'show_confirmation': True
                })
            
            # Traiter le vote
            processor = VoteProcessor(election)
            result = processor.process_vote(
                voter=request.user,
                candidate_id=candidate_id,
                request=request
            )
            
            if result['success']:
                # Stocker le reçu dans la session
                request.session['vote_receipt'] = result['receipt']
                request.session['vote_success'] = True
                
                messages.success(request, "Votre vote a été enregistré avec succès!")
                return redirect('vote:vote_success', pk=election.pk)
            else:
                # Gestion des différents types d'erreurs
                error_messages = {
                    'validation': "Erreur de validation: {}".format(result.get('error', 'Erreur inconnue')),
                    'integrity': "Erreur technique lors de l'enregistrement du vote.",
                    'system': "Erreur système. Veuillez réessayer plus tard."
                }
                
                error_message = error_messages.get(
                    result.get('error_type', 'system'),
                    "Une erreur inattendue s'est produite."
                )
                
                messages.error(request, error_message)
                
                # Log de sécurité pour les erreurs suspectes
                if result.get('error_type') in ['validation', 'integrity']:
                    SecurityEvent.create_event(
                        event_type='suspicious_activity',
                        title='Erreur lors du vote',
                        description=f'Erreur {result.get("error_type")} pour {request.user.username}: {result.get("error")}',
                        request=request,
                        user=request.user,
                        severity='medium'
                    )
                
                return self.get(request, *args, **kwargs)
                
        except Exception as e:
            logger.error(f"Erreur inattendue lors du vote: {e}")
            messages.error(request, "Une erreur technique inattendue s'est produite.")
            return self.get(request, *args, **kwargs)


class VoteSuccessView(LoginRequiredMixin, DetailView):
    """
    Vue de confirmation du vote réussi
    Exigence: Confirmation sécurisée et reçu de vote
    """
    model = Election
    template_name = 'vote/vote_success.html'
    context_object_name = 'election'
    
    def dispatch(self, request, *args, **kwargs):
        """Vérifier que l'utilisateur vient de voter"""
        if not request.session.get('vote_success'):
            return redirect('vote:elections_list')
        
        return super().dispatch(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Récupérer le reçu de vote
        receipt = self.request.session.get('vote_receipt')
        if receipt:
            context['receipt'] = receipt
            # Nettoyer la session après affichage
            del self.request.session['vote_receipt']
            del self.request.session['vote_success']
        
        # Informations sur le vote
        try:
            vote_record = VoteRecord.objects.get(
                election=self.get_object(),
                voter=self.request.user
            )
            context['vote_timestamp'] = vote_record.voted_at
        except VoteRecord.DoesNotExist:
            pass
        
        return context


class VoteConfirmationView(LoginRequiredMixin, DetailView):
    """
    Vue de confirmation que l'utilisateur a voté
    Exigence: Interface de statut de vote
    """
    model = Election
    template_name = 'vote/vote_confirmation.html'
    context_object_name = 'election'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        election = self.get_object()
        
        # Vérifier que l'utilisateur a bien voté
        try:
            vote_record = VoteRecord.objects.get(
                election=election,
                voter=self.request.user
            )
            context['vote_record'] = vote_record
            context['has_voted'] = True
        except VoteRecord.DoesNotExist:
            context['has_voted'] = False
        
        return context


class ElectionResultsView(LoginRequiredMixin, DetailView):
    """
    Vue des résultats d'élection
    Exigence: Affichage transparent des résultats
    """
    model = Election
    template_name = 'vote/election_results.html'
    context_object_name = 'election'
    
    def dispatch(self, request, *args, **kwargs):
        election = self.get_object()
        
        # Vérifier que les résultats sont publiés
        if election.status != 'closed':
            messages.error(request, "Les résultats ne sont pas encore disponibles.")
            return redirect('vote:elections_list')
        
        try:
            result = election.result
            if not result.is_published:
                messages.error(request, "Les résultats ne sont pas encore publiés.")
                return redirect('vote:elections_list')
        except ElectionResult.DoesNotExist:
            messages.error(request, "Les résultats n'ont pas encore été calculés.")
            return redirect('vote:elections_list')
        
        return super().dispatch(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        election = self.get_object()
        
        try:
            # Récupérer les résultats publics
            election_result = election.result
            context['results'] = election_result.get_public_results()
            
            # Calculer et afficher les résultats détaillés
            counter = VoteCounter(election)
            detailed_results = counter.count_votes()
            context['detailed_results'] = detailed_results
            
            # Enregistrer l'accès aux résultats
            AuditLog.log_action(
                user=self.request.user,
                action='results_viewed',
                resource='election_results',
                request=self.request,
                result='success',
                category='data_access',
                details={
                    'election_id': str(election.id),
                    'election_title': election.title
                }
            )
            
        except Exception as e:
            logger.error(f"Erreur lors de l'affichage des résultats: {e}")
            messages.error(self.request, "Erreur lors du chargement des résultats.")
        
        return context


# Vues administratives

class AdminElectionListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
    """
    Vue administrative des élections
    Exigence: Interface d'administration pour la gestion des élections
    """
    model = Election
    template_name = 'vote/admin/elections_list.html'
    context_object_name = 'elections'
    permission_required = 'vote.can_manage_elections'
    paginate_by = 20
    
    def get_queryset(self):
        return Election.objects.all().order_by('-created_at')


class AdminElectionDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
    """
    Vue administrative détaillée d'une élection
    Exigence: Monitoring et gestion des élections
    """
    model = Election
    template_name = 'vote/admin/election_detail.html'
    context_object_name = 'election'
    permission_required = 'vote.can_manage_elections'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        election = self.get_object()
        
        # Statistiques de l'élection
        context['stats'] = {
            'total_eligible_voters': election.voters.filter(is_eligible=True).count(),
            'total_votes_cast': VoteRecord.objects.filter(election=election).count(),
            'total_candidates': election.candidates.filter(is_active=True).count(),
            'encryption_enabled': bool(election.public_key),
        }
        
        # Validation cryptographique
        if election.public_key:
            context['crypto_status'] = validate_election_keys(election)
        
        # Vérification d'intégrité
        try:
            validator = VoteValidator(election)
            context['integrity_report'] = validator.validate_election_integrity()
        except Exception as e:
            logger.error(f"Erreur lors de la validation d'intégrité: {e}")
            context['integrity_error'] = str(e)
        
        return context


@method_decorator([csrf_protect], name='dispatch')
class AdminCloseElectionView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
    """
    Vue pour fermer une élection et calculer les résultats
    Exigence: Clôture sécurisée des élections
    """
    model = Election
    template_name = 'vote/admin/close_election.html'
    context_object_name = 'election'
    permission_required = 'vote.can_manage_elections'
    
    def post(self, request, *args, **kwargs):
        election = self.get_object()
        
        if election.status == 'closed':
            messages.warning(request, "Cette élection est déjà fermée.")
            return redirect('vote:admin_election_detail', pk=election.pk)
        
        try:
            with transaction.atomic():
                # Fermer l'élection
                election.close_election()
                
                # Calculer les résultats
                counter = VoteCounter(election)
                results = counter.count_votes()
                
                # Créer l'enregistrement des résultats
                election_result, created = ElectionResult.objects.get_or_create(
                    election=election,
                    defaults={
                        'calculated_by': request.user,
                        'total_votes': results['statistics']['total_valid_votes'],
                        'eligible_voters': results['statistics']['eligible_voters'],
                        'turnout_percentage': results['statistics']['turnout_percentage']
                    }
                )
                
                if created:
                    # Chiffrer et stocker les résultats détaillés
                    from .encryption import VoteEncryption
                    encryption = VoteEncryption(election)
                    
                    # TODO: Implémenter le chiffrement des résultats
                    election_result.encrypted_results = json.dumps(results)
                    election_result.results_hash = results['integrity_hash']
                    election_result.is_final = True
                    election_result.save()
                
                # Enregistrer l'événement
                AuditLog.log_action(
                    user=request.user,
                    action='election_closed',
                    resource='election',
                    request=request,
                    result='success',
                    category='election_event',
                    details={
                        'election_id': str(election.id),
                        'total_votes': results['statistics']['total_valid_votes'],
                        'turnout': f"{results['statistics']['turnout_percentage']}%"
                    }
                )
                
                messages.success(request, f"Élection fermée avec succès. {results['statistics']['total_valid_votes']} votes comptabilisés.")
                
        except Exception as e:
            logger.error(f"Erreur lors de la fermeture de l'élection: {e}")
            messages.error(request, "Erreur lors de la fermeture de l'élection.")
        
        return redirect('vote:admin_election_detail', pk=election.pk)


@method_decorator([csrf_protect], name='dispatch')
class AdminPublishResultsView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
    """
    Vue pour publier les résultats d'une élection
    Exigence: Publication contrôlée des résultats
    """
    model = Election
    template_name = 'vote/admin/publish_results.html'
    context_object_name = 'election'
    permission_required = 'vote.can_manage_elections'
    
    def post(self, request, *args, **kwargs):
        election = self.get_object()
        
        try:
            election_result = election.result
            
            if election_result.is_published:
                messages.warning(request, "Les résultats sont déjà publiés.")
                return redirect('vote:admin_election_detail', pk=election.pk)
            
            # Publier les résultats
            election_result.is_published = True
            election_result.save()
            
            # Enregistrer l'événement
            AuditLog.log_action(
                user=request.user,
                action='results_published',
                resource='election_results',
                request=request,
                result='success',
                category='election_event',
                details={
                    'election_id': str(election.id),
                    'election_title': election.title
                }
            )
            
            messages.success(request, "Résultats publiés avec succès.")
            
        except ElectionResult.DoesNotExist:
            messages.error(request, "Aucun résultat à publier. L'élection doit d'abord être fermée.")
        except Exception as e:
            logger.error(f"Erreur lors de la publication: {e}")
            messages.error(request, "Erreur lors de la publication des résultats.")
        
        return redirect('vote:admin_election_detail', pk=election.pk)


# API Views pour les interactions AJAX

@login_required
def check_vote_status(request, election_id):
    """
    API pour vérifier le statut de vote d'un utilisateur
    Exigence: Interface dynamique de statut
    """
    try:
        election = get_object_or_404(Election, id=election_id)
        
        # Vérifier l'éligibilité
        if not election.is_user_eligible(request.user):
            return JsonResponse({
                'eligible': False,
                'message': 'Non autorisé à voter dans cette élection'
            })
        
        # Vérifier si déjà voté
        has_voted = election.has_user_voted(request.user)
        
        # Statut de l'élection
        is_open = election.is_voting_open()
        
        return JsonResponse({
            'eligible': True,
            'has_voted': has_voted,
            'election_open': is_open,
            'election_status': election.status,
            'message': 'Statut récupéré avec succès'
        })
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification du statut: {e}")
        return JsonResponse({
            'error': 'Erreur lors de la vérification du statut'
        }, status=500)


@login_required
def validate_vote_choice(request, election_id):
    """
    API pour valider un choix de vote avant soumission
    Exigence: Validation côté client
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Méthode non autorisée'}, status=405)
    
    try:
        election = get_object_or_404(Election, id=election_id)
        candidate_id = request.POST.get('candidate_id')
        
        if not candidate_id:
            return JsonResponse({
                'valid': False,
                'error': 'Candidat non spécifié'
            })
        
        # Vérifier que le candidat existe
        try:
            candidate = Candidate.objects.get(
                id=candidate_id,
                election=election,
                is_active=True
            )
        except Candidate.DoesNotExist:
            return JsonResponse({
                'valid': False,
                'error': 'Candidat invalide'
            })
        
        # Validation supplémentaire
        processor = VoteProcessor(election)
        validation = processor._validate_vote_eligibility(request.user, candidate_id)
        
        if validation['valid']:
            return JsonResponse({
                'valid': True,
                'candidate_name': candidate.name,
                'message': 'Choix valide'
            })
        else:
            return JsonResponse({
                'valid': False,
                'error': validation.get('error', 'Validation échouée')
            })
            
    except Exception as e:
        logger.error(f"Erreur lors de la validation du choix: {e}")
        return JsonResponse({
            'error': 'Erreur lors de la validation'
        }, status=500)


@login_required
def election_stats_api(request, election_id):
    """
    API pour récupérer les statistiques d'une élection (pour admin)
    Exigence: Monitoring en temps réel
    """
    if not request.user.has_perm('vote.can_view_results'):
        return JsonResponse({'error': 'Permission refusée'}, status=403)
    
    try:
        election = get_object_or_404(Election, id=election_id)
        
        stats = {
            'eligible_voters': election.voters.filter(is_eligible=True).count(),
            'votes_cast': VoteRecord.objects.filter(election=election).count(),
            'participation_rate': 0,
            'election_status': election.status,
            'is_open': election.is_voting_open(),
            'time_remaining': None
        }
        
        # Calculer le taux de participation
        if stats['eligible_voters'] > 0:
            stats['participation_rate'] = round(
                (stats['votes_cast'] / stats['eligible_voters']) * 100, 2
            )
        
        # Temps restant si l'élection est ouverte
        if election.is_voting_open():
            remaining = election.end_date - timezone.now()
            stats['time_remaining'] = {
                'days': remaining.days,
                'hours': remaining.seconds // 3600,
                'minutes': (remaining.seconds % 3600) // 60
            }
        
        return JsonResponse(stats)
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des stats: {e}")
        return JsonResponse({
            'error': 'Erreur lors de la récupération des statistiques'
        }, status=500)


# Vues utilitaires

def election_integrity_check(request, election_id):
    """
    Vue pour vérifier l'intégrité d'une élection
    Exigence: Vérification d'intégrité accessible aux utilisateurs
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentification requise'}, status=401)
    
    try:
        election = get_object_or_404(Election, id=election_id)
        
        # Vérification basique pour les utilisateurs normaux
        basic_check = {
            'election_id': str(election.id),
            'election_title': election.title,
            'has_encryption': bool(election.public_key),
            'total_votes': Vote.objects.filter(election=election).count(),
            'check_timestamp': timezone.now().isoformat()
        }
        
        # Vérification complète pour les admins
        if request.user.has_perm('vote.can_view_audit_logs'):
            from .vote_processor import verify_vote_chain_integrity
            integrity_report = verify_vote_chain_integrity(election)
            basic_check.update(integrity_report)
        
        return JsonResponse(basic_check)
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification d'intégrité: {e}")
        return JsonResponse({
            'error': 'Erreur lors de la vérification'
        }, status=500)