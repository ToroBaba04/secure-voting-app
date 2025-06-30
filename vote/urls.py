# vote/urls.py - URLs pour le système de vote de GalSecVote
"""
Configuration des URLs pour le système de vote sécurisé
Exigence: Routes sécurisées pour toutes les fonctionnalités de vote
"""

from django.urls import path, include
from . import views

app_name = 'vote'

# URLs principales pour les électeurs
urlpatterns = [
    # Liste des élections disponibles
    path('', views.ActiveElectionsView.as_view(), name='elections_list'),
    
    # Interface de vote
    path('election/<uuid:pk>/vote/', views.VotingView.as_view(), name='vote'),
    path('election/<uuid:pk>/success/', views.VoteSuccessView.as_view(), name='vote_success'),
    path('election/<uuid:pk>/confirmation/', views.VoteConfirmationView.as_view(), name='vote_confirmation'),
    
    # Résultats d'élection
    path('election/<uuid:pk>/results/', views.ElectionResultsView.as_view(), name='election_results'),
    
    # APIs pour interactions AJAX
    path('api/election/<uuid:election_id>/status/', views.check_vote_status, name='api_vote_status'),
    path('api/election/<uuid:election_id>/validate/', views.validate_vote_choice, name='api_validate_choice'),
    path('api/election/<uuid:election_id>/stats/', views.election_stats_api, name='api_election_stats'),
    
    # Vérification d'intégrité
    path('election/<uuid:election_id>/integrity/', views.election_integrity_check, name='integrity_check'),
]

# URLs d'administration
admin_patterns = [
    # Gestion des élections
    path('elections/', views.AdminElectionListView.as_view(), name='admin_elections_list'),
    path('elections/<uuid:pk>/', views.AdminElectionDetailView.as_view(), name='admin_election_detail'),
    path('elections/<uuid:pk>/close/', views.AdminCloseElectionView.as_view(), name='admin_close_election'),
    path('elections/<uuid:pk>/publish/', views.AdminPublishResultsView.as_view(), name='admin_publish_results'),
]

# Ajouter les URLs d'administration avec le préfixe 'admin/'
urlpatterns += [
    path('admin/', include((admin_patterns, 'vote'), namespace='admin')),
]