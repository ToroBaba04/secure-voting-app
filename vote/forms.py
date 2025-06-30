# vote/forms.py - Formulaires pour le système de vote de GalSecVote
"""
Formulaires pour la gestion des élections et du processus de vote
Exigence: Interface utilisateur sécurisée et validation des données
"""

from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models import Q
import logging

from .models import Election, Candidate, ElectionVoter
from cryptoutils.models import KeyPair

User = get_user_model()
logger = logging.getLogger('vote.forms')


class VoteForm(forms.Form):
    """
    Formulaire pour le processus de vote
    Exigence: Interface de vote sécurisée avec validation
    """
    
    candidate = forms.ModelChoiceField(
        queryset=None,
        widget=forms.RadioSelect(attrs={
            'class': 'form-check-input candidate-choice',
            'required': True
        }),
        label="Choisissez votre candidat",
        empty_label=None,
        error_messages={
            'required': 'Vous devez sélectionner un candidat pour voter.',
            'invalid_choice': 'Le candidat sélectionné n\'est pas valide.'
        }
    )
    
    confirmation = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input',
            'id': 'vote-confirmation'
        }),
        label="Je confirme que c'est mon choix définitif",
        error_messages={
            'required': 'Vous devez confirmer votre choix pour valider le vote.'
        }
    )
    
    def __init__(self, election, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.election = election
        self.user = user
        
        # Définir les candidats disponibles
        self.fields['candidate'].queryset = election.candidates.filter(
            is_active=True
        ).order_by('order', 'name')
        
        # Personnaliser le widget pour afficher les informations des candidats
        choices = []
        for candidate in self.fields['candidate'].queryset:
            choices.append((candidate.id, candidate))
        
        self.fields['candidate'].widget.choices = choices
    
    def clean_candidate(self):
        candidate = self.cleaned_data.get('candidate')
        
        if not candidate:
            raise ValidationError("Aucun candidat sélectionné.")
        
        # Vérifier que le candidat appartient à cette élection
        if candidate.election != self.election:
            raise ValidationError("Le candidat sélectionné n'appartient pas à cette élection.")
        
        # Vérifier que le candidat est actif
        if not candidate.is_active:
            raise ValidationError("Le candidat sélectionné n'est plus disponible.")
        
        return candidate
    
    def clean(self):
        cleaned_data = super().clean()
        
        # Vérifier que l'utilisateur peut encore voter
        if self.election.has_user_voted(self.user):
            raise ValidationError("Vous avez déjà voté dans cette élection.")
        
        # Vérifier que l'élection est ouverte
        if not self.election.is_voting_open():
            raise ValidationError("Le vote n'est plus ouvert pour cette élection.")
        
        # Vérifier l'éligibilité
        if not self.election.is_user_eligible(self.user):
            raise ValidationError("Vous n'êtes pas autorisé à voter dans cette élection.")
        
        return cleaned_data


class ElectionForm(forms.ModelForm):
    """
    Formulaire pour créer/modifier une élection
    Exigence: Interface d'administration des élections
    """
    
    class Meta:
        model = Election
        fields = [
            'title', 'description', 'start_date', 'end_date',
            'require_2fa', 'allow_vote_change', 'max_votes_per_user',
            'is_anonymous'
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Titre de l\'élection'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Description de l\'élection'
            }),
            'start_date': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
            'end_date': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
            'require_2fa': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'allow_vote_change': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'max_votes_per_user': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 1,
                'max': 10
            }),
            'is_anonymous': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }
    
    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        
        if start_date and end_date:
            # Vérifier que la date de fin est après la date de début
            if end_date <= start_date:
                raise ValidationError("La date de fin doit être postérieure à la date de début.")
            
            # Vérifier que les dates sont dans le futur (pour une nouvelle élection)
            if not self.instance.pk and start_date <= timezone.now():
                raise ValidationError("La date de début doit être dans le futur.")
            
            # Vérifier la durée minimale (au moins 1 heure)
            duration = end_date - start_date
            if duration.total_seconds() < 3600:  # 1 heure
                raise ValidationError("L'élection doit durer au moins 1 heure.")
        
        return cleaned_data
    
    def save(self, commit=True):
        election = super().save(commit=False)
        
        if commit:
            election.save()
            
            # Générer les clés cryptographiques si c'est une nouvelle élection
            if not election.public_key:
                try:
                    from .encryption import generate_election_keypair
                    public_key, private_key = generate_election_keypair(election)
                    election.public_key = public_key
                    # TODO: Stocker la clé privée de manière sécurisée
                    election.save()
                    
                    logger.info(f"Clés cryptographiques générées pour l'élection {election.id}")
                    
                except Exception as e:
                    logger.error(f"Erreur lors de la génération des clés: {e}")
                    raise ValidationError("Erreur lors de la génération des clés cryptographiques.")
        
        return election


class CandidateForm(forms.ModelForm):
    """
    Formulaire pour ajouter/modifier un candidat
    Exigence: Gestion des candidats pour les élections
    """
    
    class Meta:
        model = Candidate
        fields = ['name', 'description', 'image', 'order']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Nom du candidat'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Description du candidat (optionnel)'
            }),
            'image': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': 'image/*'
            }),
            'order': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 0
            })
        }
    
    def __init__(self, election, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.election = election
        
        # Définir l'ordre par défaut
        if not self.instance.pk:
            max_order = self.election.candidates.aggregate(
                max_order=models.Max('order')
            )['max_order'] or 0
            self.fields['order'].initial = max_order + 1
    
    def clean_name(self):
        name = self.cleaned_data.get('name')
        
        if not name or not name.strip():
            raise ValidationError("Le nom du candidat est requis.")
        
        # Vérifier l'unicité du nom dans cette élection
        existing = Candidate.objects.filter(
            election=self.election,
            name__iexact=name.strip()
        )
        
        if self.instance.pk:
            existing = existing.exclude(pk=self.instance.pk)
        
        if existing.exists():
            raise ValidationError("Un candidat avec ce nom existe déjà dans cette élection.")
        
        return name.strip()
    
    def clean_image(self):
        image = self.cleaned_data.get('image')
        
        if image:
            # Vérifier la taille du fichier (max 5MB)
            if image.size > 5 * 1024 * 1024:
                raise ValidationError("La taille de l'image ne doit pas dépasser 5MB.")
            
            # Vérifier le type de fichier
            allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
            if hasattr(image, 'content_type') and image.content_type not in allowed_types:
                raise ValidationError("Format d'image non supporté. Utilisez JPEG, PNG, GIF ou WebP.")
        
        return image
    
    def save(self, commit=True):
        candidate = super().save(commit=False)
        candidate.election = self.election
        
        if commit:
            candidate.save()
            logger.info(f"Candidat {candidate.name} ajouté à l'élection {self.election.id}")
        
        return candidate


class ElectionVoterForm(forms.ModelForm):
    """
    Formulaire pour ajouter des électeurs à une élection
    Exigence: Gestion des électeurs autorisés
    """
    
    user = forms.ModelChoiceField(
        queryset=None,
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        label="Utilisateur",
        help_text="Sélectionnez l'utilisateur à ajouter comme électeur"
    )
    
    class Meta:
        model = ElectionVoter
        fields = ['user', 'is_eligible', 'can_vote_until', 'notes']
        widgets = {
            'is_eligible': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'can_vote_until': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2,
                'placeholder': 'Notes optionnelles'
            })
        }
    
    def __init__(self, election, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.election = election
        
        # Exclure les utilisateurs déjà ajoutés à cette élection
        existing_voters = ElectionVoter.objects.filter(
            election=election
        ).values_list('user_id', flat=True)
        
        self.fields['user'].queryset = User.objects.filter(
            is_active=True
        ).exclude(
            id__in=existing_voters
        ).order_by('username')
        
        # Définir la date limite par défaut
        if not self.instance.pk:
            self.fields['can_vote_until'].initial = election.end_date
    
    def clean_can_vote_until(self):
        can_vote_until = self.cleaned_data.get('can_vote_until')
        
        if can_vote_until:
            # Vérifier que la date n'est pas antérieure à maintenant
            if can_vote_until <= timezone.now():
                raise ValidationError("La date limite de vote doit être dans le futur.")
            
            # Vérifier que la date n'est pas postérieure à la fin de l'élection
            if can_vote_until > self.election.end_date:
                raise ValidationError("La date limite ne peut pas dépasser la fin de l'élection.")
        
        return can_vote_until
    
    def save(self, commit=True):
        voter = super().save(commit=False)
        voter.election = self.election
        
        if commit:
            voter.save()
            logger.info(f"Électeur {voter.user.username} ajouté à l'élection {self.election.id}")
        
        return voter


class BulkVoterImportForm(forms.Form):
    """
    Formulaire pour l'import en masse d'électeurs
    Exigence: Gestion efficace des grandes listes d'électeurs
    """
    
    import_method = forms.ChoiceField(
        choices=[
            ('email_list', 'Liste d\'emails (un par ligne)'),
            ('username_list', 'Liste de noms d\'utilisateur (un par ligne)'),
            ('csv_file', 'Fichier CSV')
        ],
        widget=forms.RadioSelect(attrs={
            'class': 'form-check-input'
        }),
        label="Méthode d'import",
        initial='email_list'
    )
    
    email_list = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 10,
            'placeholder': 'user1@esp.sn\nuser2@esp.sn\nuser3@esp.sn'
        }),
        label="Liste d'emails",
        help_text="Un email par ligne"
    )
    
    username_list = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 10,
            'placeholder': 'user1\nuser2\nuser3'
        }),
        label="Liste de noms d'utilisateur",
        help_text="Un nom d'utilisateur par ligne"
    )
    
    csv_file = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.csv'
        }),
        label="Fichier CSV",
        help_text="Format: email,nom_utilisateur (optionnel)"
    )
    
    set_eligible = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        label="Marquer comme éligible",
        help_text="Les électeurs importés seront automatiquement éligibles"
    )
    
    def __init__(self, election, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.election = election
    
    def clean(self):
        cleaned_data = super().clean()
        import_method = cleaned_data.get('import_method')
        
        if import_method == 'email_list':
            if not cleaned_data.get('email_list'):
                raise ValidationError("La liste d'emails est requise pour cette méthode.")
        elif import_method == 'username_list':
            if not cleaned_data.get('username_list'):
                raise ValidationError("La liste de noms d'utilisateur est requise pour cette méthode.")
        elif import_method == 'csv_file':
            if not cleaned_data.get('csv_file'):
                raise ValidationError("Le fichier CSV est requis pour cette méthode.")
        
        return cleaned_data
    
    def clean_csv_file(self):
        csv_file = self.cleaned_data.get('csv_file')
        
        if csv_file:
            # Vérifier la taille du fichier (max 1MB)
            if csv_file.size > 1024 * 1024:
                raise ValidationError("Le fichier CSV ne doit pas dépasser 1MB.")
            
            # Vérifier l'extension
            if not csv_file.name.lower().endswith('.csv'):
                raise ValidationError("Le fichier doit avoir l'extension .csv")
        
        return csv_file
    
    def process_import(self, added_by):
        """
        Traite l'import des électeurs
        
        Args:
            added_by: Utilisateur qui effectue l'import
            
        Returns:
            Dict avec les résultats de l'import
        """
        import_method = self.cleaned_data['import_method']
        set_eligible = self.cleaned_data.get('set_eligible', True)
        
        results = {
            'success': 0,
            'errors': 0,
            'duplicates': 0,
            'not_found': 0,
            'details': []
        }
        
        users_to_add = []
        
        try:
            if import_method == 'email_list':
                email_list = self.cleaned_data['email_list'].strip().split('\n')
                for email in email_list:
                    email = email.strip()
                    if email:
                        try:
                            user = User.objects.get(email=email, is_active=True)
                            users_to_add.append(user)
                        except User.DoesNotExist:
                            results['not_found'] += 1
                            results['details'].append(f"Utilisateur non trouvé: {email}")
            
            elif import_method == 'username_list':
                username_list = self.cleaned_data['username_list'].strip().split('\n')
                for username in username_list:
                    username = username.strip()
                    if username:
                        try:
                            user = User.objects.get(username=username, is_active=True)
                            users_to_add.append(user)
                        except User.DoesNotExist:
                            results['not_found'] += 1
                            results['details'].append(f"Utilisateur non trouvé: {username}")
            
            elif import_method == 'csv_file':
                import csv
                csv_file = self.cleaned_data['csv_file']
                decoded_file = csv_file.read().decode('utf-8').splitlines()
                reader = csv.DictReader(decoded_file)
                
                for row in reader:
                    email = row.get('email', '').strip()
                    username = row.get('username', '').strip()
                    
                    if email:
                        try:
                            user = User.objects.get(email=email, is_active=True)
                            users_to_add.append(user)
                        except User.DoesNotExist:
                            results['not_found'] += 1
                            results['details'].append(f"Utilisateur non trouvé: {email}")
                    elif username:
                        try:
                            user = User.objects.get(username=username, is_active=True)
                            users_to_add.append(user)
                        except User.DoesNotExist:
                            results['not_found'] += 1
                            results['details'].append(f"Utilisateur non trouvé: {username}")
            
            # Ajouter les utilisateurs trouvés
            for user in users_to_add:
                try:
                    # Vérifier si déjà électeur
                    if ElectionVoter.objects.filter(election=self.election, user=user).exists():
                        results['duplicates'] += 1
                        results['details'].append(f"Déjà électeur: {user.username}")
                        continue
                    
                    # Créer l'électeur
                    ElectionVoter.objects.create(
                        election=self.election,
                        user=user,
                        is_eligible=set_eligible,
                        added_by=added_by
                    )
                    
                    results['success'] += 1
                    
                except Exception as e:
                    results['errors'] += 1
                    results['details'].append(f"Erreur pour {user.username}: {str(e)}")
            
            logger.info(f"Import d'électeurs terminé pour l'élection {self.election.id}: {results['success']} ajoutés")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'import d'électeurs: {e}")
            results['errors'] += 1
            results['details'].append(f"Erreur générale: {str(e)}")
        
        return results


class ElectionSearchForm(forms.Form):
    """
    Formulaire de recherche d'élections
    Exigence: Interface de recherche et filtrage
    """
    
    search = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Rechercher par titre...'
        }),
        label="Recherche"
    )
    
    status = forms.ChoiceField(
        required=False,
        choices=[('', 'Tous les statuts')] + Election.STATUS_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        label="Statut"
    )
    
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        }),
        label="Date de début (à partir de)"
    )
    
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        }),
        label="Date de début (jusqu'à)"
    )
    
    created_by = forms.ModelChoiceField(
        required=False,
        queryset=User.objects.filter(is_active=True).order_by('username'),
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        label="Créé par",
        empty_label="Tous les créateurs"
    )
    
    def filter_queryset(self, queryset):
        """
        Applique les filtres à un queryset d'élections
        
        Args:
            queryset: QuerySet d'élections à filtrer
            
        Returns:
            QuerySet filtré
        """
        if not self.is_valid():
            return queryset
        
        search = self.cleaned_data.get('search')
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) | Q(description__icontains=search)
            )
        
        status = self.cleaned_data.get('status')
        if status:
            queryset = queryset.filter(status=status)
        
        date_from = self.cleaned_data.get('date_from')
        if date_from:
            queryset = queryset.filter(start_date__gte=date_from)
        
        date_to = self.cleaned_data.get('date_to')
        if date_to:
            queryset = queryset.filter(start_date__lte=date_to)
        
        created_by = self.cleaned_data.get('created_by')
        if created_by:
            queryset = queryset.filter(created_by=created_by)
        
        return queryset


class VoteVerificationForm(forms.Form):
    """
    Formulaire pour vérifier un vote avec son reçu
    Exigence: Vérification de vote par l'électeur
    """
    
    receipt_id = forms.CharField(
        max_length=32,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'ID du reçu de vote'
        }),
        label="ID du reçu",
        help_text="Entrez l'ID du reçu que vous avez reçu après avoir voté"
    )
    
    verification_code = forms.CharField(
        max_length=12,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Code de vérification'
        }),
        label="Code de vérification",
        help_text="Code de vérification à 12 caractères de votre reçu"
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def clean_receipt_id(self):
        receipt_id = self.cleaned_data.get('receipt_id')
        
        if not receipt_id:
            raise ValidationError("L'ID du reçu est requis.")
        
        # Vérifier le format (32 caractères hexadécimaux)
        if not all(c in '0123456789abcdef' for c in receipt_id.lower()):
            raise ValidationError("Format d'ID de reçu invalide.")
        
        if len(receipt_id) != 32:
            raise ValidationError("L'ID du reçu doit contenir exactement 32 caractères.")
        
        return receipt_id.lower()
    
    def clean_verification_code(self):
        verification_code = self.cleaned_data.get('verification_code')
        
        if not verification_code:
            raise ValidationError("Le code de vérification est requis.")
        
        # Vérifier le format (12 caractères hexadécimaux)
        if not all(c in '0123456789abcdef' for c in verification_code.lower()):
            raise ValidationError("Format de code de vérification invalide.")
        
        if len(verification_code) != 12:
            raise ValidationError("Le code de vérification doit contenir exactement 12 caractères.")
        
        return verification_code.lower()
    
    def verify_vote(self, election=None):
        """
        Vérifie le vote avec les informations du reçu
        
        Args:
            election: Élection dans laquelle vérifier (optionnel)
            
        Returns:
            Dict avec le résultat de la vérification
        """
        if not self.is_valid():
            return {
                'verified': False,
                'error': 'Formulaire invalide',
                'details': self.errors
            }
        
        receipt_id = self.cleaned_data['receipt_id']
        verification_code = self.cleaned_data['verification_code']
        
        try:
            # TODO: Implémenter la logique de vérification réelle
            # Pour l'instant, simulation basique
            
            # Dans une implémentation réelle, on rechercherait dans une base
            # de reçus ou on recalculerait le hash de vérification
            
            return {
                'verified': True,
                'receipt_id': receipt_id,
                'verification_code': verification_code,
                'message': 'Vote vérifié avec succès',
                'election_id': election.id if election else None
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du vote: {e}")
            return {
                'verified': False,
                'error': 'Erreur technique lors de la vérification',
                'details': str(e)
            }


# Formulaires pour l'administration avancée

class ElectionSecuritySettingsForm(forms.ModelForm):
    """
    Formulaire pour les paramètres de sécurité avancés d'une élection
    Exigence: Configuration de sécurité granulaire
    """
    
    encryption_key_size = forms.ChoiceField(
        choices=[
            (2048, '2048 bits (Standard)'),
            (3072, '3072 bits (Renforcé)'),
            (4096, '4096 bits (Maximum)')
        ],
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        label="Taille de clé de chiffrement",
        initial=2048
    )
    
    signature_algorithm = forms.ChoiceField(
        choices=[
            ('PSS', 'RSA-PSS (Recommandé)'),
            ('PKCS1v15', 'RSA-PKCS1v15 (Classique)')
        ],
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        label="Algorithme de signature",
        initial='PSS'
    )
    
    audit_level = forms.ChoiceField(
        choices=[
            ('basic', 'Basique'),
            ('detailed', 'Détaillé'),
            ('comprehensive', 'Complet')
        ],
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        label="Niveau d'audit",
        initial='detailed'
    )
    
    class Meta:
        model = Election
        fields = ['require_2fa', 'is_anonymous', 'allow_vote_change']
        widgets = {
            'require_2fa': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'is_anonymous': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'allow_vote_change': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Si l'élection existe déjà, récupérer les paramètres actuels
        if self.instance and self.instance.pk:
            # TODO: Récupérer les paramètres de sécurité depuis la base
            pass
    
    def save(self, commit=True):
        election = super().save(commit=False)
        
        if commit:
            election.save()
            
            # TODO: Appliquer les paramètres de sécurité avancés
            # Sauvegarder dans une table de configuration séparée
            
            logger.info(f"Paramètres de sécurité mis à jour pour l'élection {election.id}")
        
        return election