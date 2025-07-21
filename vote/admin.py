
# vote/admin.py - Interface d'administration pour le système de vote
"""
Configuration de l'interface d'administration Django pour le système de vote
Exigence: Interface d'administration sécurisée pour les élections
"""

from django.contrib import admin
from django.utils.html import format_html
from django.db.models import Count

from .models import Election, Candidate, Vote, VoteRecord, ElectionVoter, ElectionResult


@admin.register(Election)
class ElectionAdmin(admin.ModelAdmin):
    """Administration pour les élections"""
    
    list_display = ('title', 'status', 'start_date', 'end_date', 'votes_count', 'created_by')
    list_filter = ('status', 'start_date', 'end_date', 'is_active')
    search_fields = ('title', 'description')
    readonly_fields = ('id', 'created_at', 'public_key', 'private_key_hash')
    
    fieldsets = (
        ('Informations générales', {
            'fields': ('title', 'description', 'created_by')
        }),
        ('Période de vote', {
            'fields': ('start_date', 'end_date')
        }),
        ('Statut', {
            'fields': ('status', 'is_active')
        }),
        ('Cryptographie', {
            'fields': ('public_key', 'private_key_hash'),
            'classes': ('collapse',)
        }),
        ('Métadonnées', {
            'fields': ('id', 'created_at'),
            'classes': ('collapse',)
        }),
    )
    
    def votes_count(self, obj):
        return obj.votes.count()
    votes_count.short_description = 'Nombre de votes'


class CandidateInline(admin.TabularInline):
    """Inline pour les candidats dans l'élection"""
    model = Candidate
    extra = 1
    fields = ('name', 'description', 'order', 'is_active')


@admin.register(Candidate)
class CandidateAdmin(admin.ModelAdmin):
    """Administration pour les candidats"""
    
    list_display = ('name', 'election', 'order', 'votes_count', 'is_active')
    list_filter = ('election', 'is_active', 'created_at')
    search_fields = ('name', 'election__title')
    
    fieldsets = (
        ('Informations', {
            'fields': ('election', 'name', 'description', 'image')
        }),
        ('Configuration', {
            'fields': ('order', 'is_active')
        }),
    )
    
    def votes_count(self, obj):
        return obj.get_votes_count()
    votes_count.short_description = 'Votes reçus'


@admin.register(Vote)
class VoteAdmin(admin.ModelAdmin):
    """Administration pour les votes (lecture seule)"""
    
    list_display = ('vote_token_short', 'election', 'timestamp', 'is_valid', 'is_counted')
    list_filter = ('election', 'is_valid', 'is_counted', 'timestamp')
    search_fields = ('vote_token',)
    readonly_fields = ('id', 'election', 'encrypted_choice', 'choice_hash', 'digital_signature', 
                      'vote_token', 'timestamp', 'ip_hash')
    
    def vote_token_short(self, obj):
        return f"{obj.vote_token[:8]}..."
    vote_token_short.short_description = 'Token'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(VoteRecord)
class VoteRecordAdmin(admin.ModelAdmin):
    """Administration pour les enregistrements de vote"""
    
    list_display = ('voter', 'election', 'voted_at', 'is_verified', 'verification_method')
    list_filter = ('election', 'is_verified', 'verification_method', 'voted_at')
    search_fields = ('voter__username', 'election__title')
    readonly_fields = ('voter', 'election', 'voted_at', 'vote_token', 'ip_address', 'user_agent')


@admin.register(ElectionVoter)
class ElectionVoterAdmin(admin.ModelAdmin):
    """Administration pour les électeurs autorisés"""
    
    list_display = ('user', 'election', 'is_eligible', 'added_at', 'added_by')
    list_filter = ('election', 'is_eligible', 'added_at')
    search_fields = ('user__username', 'election__title')
    
    fieldsets = (
        ('Électeur', {
            'fields': ('election', 'user', 'added_by')
        }),
        ('Autorisation', {
            'fields': ('is_eligible', 'can_vote_until', 'notes')
        }),
    )


@admin.register(ElectionResult)
class ElectionResultAdmin(admin.ModelAdmin):
    """Administration pour les résultats d'élections"""
    
    list_display = ('election', 'calculated_by', 'calculated_at', 'is_final', 'is_published')
    list_filter = ('is_final', 'is_published', 'calculated_at')
    search_fields = ('election__title',)
    readonly_fields = ('calculated_at', 'encrypted_results', 'results_hash')
