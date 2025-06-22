"""
Modèles pour le système de vote électronique sécurisé de GalSecVote
Implémentation des exigences de chiffrement, intégrité et anonymat
"""

from django.db import models
from django.utils import timezone
from django.core.validators import MinValueValidator
from django.contrib.auth import get_user_model
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import json
import uuid
import hashlib
from datetime import timedelta

User = get_user_model()


class Election(models.Model):
    """
    Modèle d'élection
    Exigence: Gestion des scrutins avec sécurité renforcée
    """
    
    # Informations de base
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200, verbose_name="Titre de l'élection")
    description = models.TextField(verbose_name="Description")
    
    # Créateur et permissions
    created_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='created_elections')
    
    # Dates et timing
    created_at = models.DateTimeField(auto_now_add=True)
    start_date = models.DateTimeField(verbose_name="Date de début")
    end_date = models.DateTimeField(verbose_name="Date de fin")
    
    # Statuts
    STATUS_CHOICES = [
        ('draft', 'Brouillon'),
        ('published', 'Publiée'),
        ('active', 'En cours'),
        ('closed', 'Fermée'),
        ('archived', 'Archivée'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    
    # Configuration de sécurité
    require_2fa = models.BooleanField(default=True, verbose_name="Exiger 2FA")
    allow_vote_change = models.BooleanField(default=False, verbose_name="Autoriser modification du vote")
    max_votes_per_user = models.PositiveIntegerField(default=1, validators=[MinValueValidator(1)])
    
    # Chiffrement
    public_key = models.TextField(verbose_name="Clé publique de chiffrement")
    private_key_hash = models.CharField(max_length=64, verbose_name="Hash de la clé privée")
    
    # Métadonnées d'audit
    is_active = models.BooleanField(default=False)
    is_anonymous = models.BooleanField(default=True, verbose_name="Vote anonyme")
    
    class Meta:
        verbose_name = "Élection"
        verbose_name_plural = "Élections"
        ordering = ['-created_at']
        permissions = [
            ("can_create_election", "Peut créer une élection"),
            ("can_close_election", "Peut fermer une élection"),
            ("can_view_results", "Peut voir les résultats"),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.status})"
    
    def is_voting_open(self):
        """Vérifie si le vote est ouvert"""
        now = timezone.now()
        return (
            self.status == 'active' and
            self.start_date <= now <= self.end_date and
            self.is_active
        )
    
    def is_user_eligible(self, user):
        """Vérifie si un utilisateur peut voter"""
        if not self.is_voting_open():
            return False
        
        # Vérifier si l'utilisateur est dans la liste des électeurs
        return ElectionVoter.objects.filter(
            election=self,
            user=user,
            is_eligible=True
        ).exists()
    
    def has_user_voted(self, user):
        """Vérifie si un utilisateur a déjà voté"""
        return VoteRecord.objects.filter(
            election=self,
            voter=user
        ).exists()
    
    def get_votes_count(self):
        """Retourne le nombre total de votes"""
        return Vote.objects.filter(election=self).count()
    
    def close_election(self):
        """Ferme l'élection"""
        self.status = 'closed'
        self.is_active = False
        self.save()
    
    def generate_key_pair(self):
        """Génère une paire de clés RSA pour l'élection"""
        from cryptoutils.rsa_manager import RSAManager
        rsa_manager = RSAManager()
        public_key, private_key = rsa_manager.generate_key_pair()
        
        self.public_key = public_key
        # Stocker seulement le hash de la clé privée pour audit
        self.private_key_hash = hashlib.sha256(private_key.encode()).hexdigest()
        self.save()
        
        return public_key, private_key


class Candidate(models.Model):
    """
    Candidat ou option de vote
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    election = models.ForeignKey(Election, on_delete=models.CASCADE, related_name='candidates')
    
    name = models.CharField(max_length=200, verbose_name="Nom du candidat/option")
    description = models.TextField(blank=True, verbose_name="Description")
    image = models.ImageField(upload_to='candidates/', blank=True, null=True)
    
    # Ordre d'affichage
    order = models.PositiveIntegerField(default=0)
    
    # Métadonnées
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['order', 'name']
        unique_together = ['election', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.election.title})"
    
    def get_votes_count(self):
        """Retourne le nombre de votes pour ce candidat"""
        return Vote.objects.filter(
            election=self.election,
            choice_hash=self.get_choice_hash()
        ).count()
    
    def get_choice_hash(self):
        """Génère un hash pour ce choix (anonymisation)"""
        return hashlib.sha256(f"{self.election.id}:{self.id}".encode()).hexdigest()


class ElectionVoter(models.Model):
    """
    Liste des électeurs autorisés pour une élection
    Exigence: Contrôle d'accès et autorisation
    """
    election = models.ForeignKey(Election, on_delete=models.CASCADE, related_name='voters')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='elections')
    
    # Statuts d'éligibilité
    is_eligible = models.BooleanField(default=True)
    added_at = models.DateTimeField(auto_now_add=True)
    added_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='added_voters')
    
    # Restrictions spécifiques
    can_vote_until = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    
    class Meta:
        unique_together = ['election', 'user']
        verbose_name = "Électeur autorisé"
        verbose_name_plural = "Électeurs autorisés"
    
    def __str__(self):
        return f"{self.user.username} → {self.election.title}"
    
    def is_voting_allowed(self):
        """Vérifie si le vote est autorisé pour cet électeur"""
        if not self.is_eligible:
            return False
        
        if self.can_vote_until and timezone.now() > self.can_vote_until:
            return False
        
        return self.election.is_voting_open()


class Vote(models.Model):
    """
    Vote chiffré et anonymisé
    Exigence: Confidentialité, intégrité et anonymat
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    election = models.ForeignKey(Election, on_delete=models.CASCADE, related_name='votes')
    
    # Vote chiffré (pas de lien direct avec l'utilisateur)
    encrypted_choice = models.TextField(verbose_name="Choix chiffré")
    choice_hash = models.CharField(max_length=64, verbose_name="Hash du choix")
    
    # Signature numérique pour l'intégrité
    digital_signature = models.TextField(verbose_name="Signature numérique")
    
    # Métadonnées anonymisées
    vote_token = models.CharField(max_length=64, unique=True, verbose_name="Token de vote")
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_hash = models.CharField(max_length=64, verbose_name="Hash IP")
    
    # Validation
    is_valid = models.BooleanField(default=True)
    is_counted = models.BooleanField(default=True)
    
    class Meta:
        verbose_name = "Vote"
        verbose_name_plural = "Votes"
        ordering = ['timestamp']
    
    def __str__(self):
        return f"Vote {self.vote_token[:8]}... ({self.election.title})"
    
    @classmethod
    def create_encrypted_vote(cls, election, candidate, voter_ip):
        """Crée un vote chiffré et anonymisé"""
        from cryptoutils.rsa_manager import RSAManager
        
        # Générer un token unique pour ce vote
        vote_token = hashlib.sha256(
            f"{election.id}:{candidate.id}:{timezone.now().isoformat()}".encode()
        ).hexdigest()
        
        # Chiffrer le choix
        rsa_manager = RSAManager()
        encrypted_choice = rsa_manager.encrypt_data(
            str(candidate.id), 
            election.public_key
        )
        
        # Hash du choix pour comptage anonyme
        choice_hash = candidate.get_choice_hash()
        
        # Hash de l'IP pour audit sans identification
        ip_hash = hashlib.sha256(voter_ip.encode()).hexdigest()
        
        # Signature numérique
        vote_data = f"{election.id}:{choice_hash}:{vote_token}"
        digital_signature = rsa_manager.sign_data(vote_data, election.public_key)
        
        return cls.objects.create(
            election=election,
            encrypted_choice=encrypted_choice,
            choice_hash=choice_hash,
            digital_signature=digital_signature,
            vote_token=vote_token,
            ip_hash=ip_hash
        )
    
    def verify_signature(self):
        """Vérifie la signature numérique du vote"""
        from cryptoutils.rsa_manager import RSAManager
        rsa_manager = RSAManager()
        
        vote_data = f"{self.election.id}:{self.choice_hash}:{self.vote_token}"
        return rsa_manager.verify_signature(
            vote_data, 
            self.digital_signature, 
            self.election.public_key
        )


class VoteRecord(models.Model):
    """
    Enregistrement du fait qu'un utilisateur a voté (sans le choix)
    Exigence: Prévention du double vote + audit
    """
    election = models.ForeignKey(Election, on_delete=models.CASCADE, related_name='vote_records')
    voter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='vote_records')
    
    # Métadonnées de vote
    voted_at = models.DateTimeField(auto_now_add=True)
    vote_token = models.CharField(max_length=64, verbose_name="Token de vote")
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    
    # Vérifications
    is_verified = models.BooleanField(default=True)
    verification_method = models.CharField(max_length=50, default='2fa')
    
    class Meta:
        unique_together = ['election', 'voter']
        verbose_name = "Enregistrement de vote"
        verbose_name_plural = "Enregistrements de votes"
    
    def __str__(self):
        return f"{self.voter.username} a voté dans {self.election.title}"


class ElectionResult(models.Model):
    """
    Résultats calculés d'une élection
    Exigence: Transparence et intégrité des résultats
    """
    election = models.OneToOneField(Election, on_delete=models.CASCADE, related_name='result')
    
    # Données de résultat chiffrées
    encrypted_results = models.TextField(verbose_name="Résultats chiffrés")
    results_hash = models.CharField(max_length=64, verbose_name="Hash des résultats")
    
    # Métadonnées
    calculated_at = models.DateTimeField(auto_now_add=True)
    calculated_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='calculated_results')
    
    # Validation
    is_final = models.BooleanField(default=False)
    is_published = models.BooleanField(default=False)
    
    # Statistiques publiques (anonymisées)
    total_votes = models.PositiveIntegerField(default=0)
    eligible_voters = models.PositiveIntegerField(default=0)
    turnout_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    
    class Meta:
        verbose_name = "Résultat d'élection"
        verbose_name_plural = "Résultats d'élections"
    
    def __str__(self):
        return f"Résultats de {self.election.title}"
    
    def calculate_results(self):
        """Calcule les résultats de l'élection"""
        from collections import Counter
        
        # Compter les votes par candidat (via les hash)
        votes = Vote.objects.filter(
            election=self.election,
            is_valid=True,
            is_counted=True
        )
        
        vote_counts = Counter(vote.choice_hash for vote in votes)
        
        # Préparer les résultats
        results = {}
        for candidate in self.election.candidates.all():
            choice_hash = candidate.get_choice_hash()
            results[candidate.name] = vote_counts.get(choice_hash, 0)
        
        # Chiffrer les résultats détaillés
        from cryptoutils.rsa_manager import RSAManager
        rsa_manager = RSAManager()
        self.encrypted_results = rsa_manager.encrypt_data(
            json.dumps(results), 
            self.election.public_key
        )
        
        # Calculer les statistiques publiques
        self.total_votes = votes.count()
        self.eligible_voters = self.election.voters.filter(is_eligible=True).count()
        if self.eligible_voters > 0:
            self.turnout_percentage = (self.total_votes / self.eligible_voters) * 100
        
        # Hash pour intégrité
        self.results_hash = hashlib.sha256(
            json.dumps(results, sort_keys=True).encode()
        ).hexdigest()
        
        self.save()
        return results
    
    def get_public_results(self):
        """Retourne les résultats publics (si autorisé)"""
        if not self.is_published:
            return None
        
        return {
            'total_votes': self.total_votes,
            'eligible_voters': self.eligible_voters,
            'turnout_percentage': float(self.turnout_percentage),
            'calculated_at': self.calculated_at.isoformat(),
        }