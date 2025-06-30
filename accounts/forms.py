# accounts/forms.py - Formulaires d'authentification 2FA pour GalSecVote
"""
Formulaires pour l'authentification sécurisée avec 2FA
Implémentation des exigences d'authentification forte
"""

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.conf import settings
import pyotp
import qrcode
import io
import base64
from .models import User, TwoFactorAuth
from .validators import get_password_validators_from_settings
import logging

logger = logging.getLogger('accounts')


class SecureLoginForm(AuthenticationForm):
    """
    Formulaire de connexion sécurisé avec gestion des tentatives
    Exigence: Authentification forte avec protection contre les attaques par force brute
    """
    
    username = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Adresse email',
            'autocomplete': 'email',
            'required': True
        }),
        label="Adresse email"
    )
    
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Mot de passe',
            'autocomplete': 'current-password',
            'required': True
        }),
        label="Mot de passe"
    )
    
    remember_me = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        label="Se souvenir de moi"
    )
    
    def __init__(self, request=None, *args, **kwargs):
        super().__init__(request, *args, **kwargs)
        self.request = request
        self.user_cache = None
    
    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        
        if username and password:
            # Vérifier si l'utilisateur existe et n'est pas verrouillé
            try:
                user = User.objects.get(email=username)
                
                # Vérifier le verrouillage du compte
                if user.is_account_locked():
                    logger.warning(f"Tentative de connexion sur compte verrouillé: {username}")
                    raise ValidationError(
                        _("Votre compte est temporairement verrouillé en raison de trop nombreuses tentatives de connexion. Veuillez réessayer plus tard."),
                        code='account_locked'
                    )
                
                # Authentifier l'utilisateur
                self.user_cache = authenticate(
                    self.request,
                    username=username,
                    password=password
                )
                
                if self.user_cache is None:
                    # Incrémenter les tentatives échouées
                    user.increment_failed_login()
                    logger.warning(f"Échec d'authentification pour: {username}")
                    raise ValidationError(
                        _("Adresse email ou mot de passe incorrect."),
                        code='invalid_login'
                    )
                else:
                    # Réinitialiser les tentatives échouées en cas de succès
                    user.reset_failed_login()
                    logger.info(f"Authentification réussie pour: {username}")
                
            except User.DoesNotExist:
                # Simuler le même temps de traitement pour éviter l'énumération
                authenticate(self.request, username=username, password=password)
                logger.warning(f"Tentative de connexion avec email inexistant: {username}")
                raise ValidationError(
                    _("Adresse email ou mot de passe incorrect."),
                    code='invalid_login'
                )
        
        return self.cleaned_data


class TwoFactorSetupForm(forms.Form):
    """
    Formulaire pour configurer l'authentification à deux facteurs
    Exigence: Configuration 2FA avec TOTP
    """
    
    verification_code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-control text-center',
            'placeholder': '000000',
            'autocomplete': 'one-time-code',
            'pattern': '[0-9]{6}',
            'inputmode': 'numeric'
        }),
        label="Code de vérification (6 chiffres)",
        help_text="Entrez le code affiché dans votre application d'authentification"
    )
    
    def __init__(self, user, secret_key, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.secret_key = secret_key
    
    def clean_verification_code(self):
        code = self.cleaned_data.get('verification_code')
        
        if not code or not code.isdigit():
            raise ValidationError(_("Le code doit contenir exactement 6 chiffres."))
        
        # Vérifier le code TOTP
        totp = pyotp.TOTP(self.secret_key)
        if not totp.verify(code, valid_window=2):
            logger.warning(f"Code 2FA invalide pour l'utilisateur {self.user.username}")
            raise ValidationError(_("Code de vérification invalide. Veuillez réessayer."))
        
        return code


class TwoFactorVerifyForm(forms.Form):
    """
    Formulaire de vérification 2FA lors de la connexion
    Exigence: Vérification TOTP obligatoire
    """
    
    code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-control text-center',
            'placeholder': '000000',
            'autocomplete': 'one-time-code',
            'pattern': '[0-9]{6}',
            'inputmode': 'numeric',
            'autofocus': True
        }),
        label="Code d'authentification",
        help_text="Entrez le code à 6 chiffres de votre application d'authentification"
    )
    
    backup_token = forms.CharField(
        max_length=16,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Token de récupération',
            'style': 'display: none;'
        }),
        label="Token de récupération (optionnel)"
    )
    
    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
    
    def clean(self):
        cleaned_data = super().clean()
        code = cleaned_data.get('code')
        backup_token = cleaned_data.get('backup_token')
        
        if not code and not backup_token:
            raise ValidationError(_("Veuillez entrer un code d'authentification ou un token de récupération."))
        
        try:
            two_factor = self.user.two_factor
        except TwoFactorAuth.DoesNotExist:
            logger.error(f"Tentative de vérification 2FA pour utilisateur sans 2FA configuré: {self.user.username}")
            raise ValidationError(_("L'authentification à deux facteurs n'est pas configurée pour ce compte."))
        
        # Vérifier le code TOTP ou le token de récupération
        if code:
            if not two_factor.verify_token(code):
                logger.warning(f"Code 2FA invalide pour {self.user.username}")
                raise ValidationError(_("Code d'authentification invalide."))
        elif backup_token:
            if not two_factor.use_backup_token(backup_token):
                logger.warning(f"Token de récupération invalide pour {self.user.username}")
                raise ValidationError(_("Token de récupération invalide ou déjà utilisé."))
        
        return cleaned_data


class SecureUserCreationForm(UserCreationForm):
    """
    Formulaire d'inscription sécurisé avec validation renforcée
    Exigence: Création de compte avec politique de mots de passe forte
    """
    
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'votre.email@exemple.com'
        }),
        help_text="Utilisez votre adresse email institutionnelle"
    )
    
    first_name = forms.CharField(
        max_length=50,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Prénom'
        })
    )
    
    last_name = forms.CharField(
        max_length=50,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nom'
        })
    )
    
    password1 = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Mot de passe sécurisé'
        }),
        help_text="Utilisez au moins 12 caractères avec majuscules, minuscules, chiffres et caractères spéciaux."
    )
    
    password2 = forms.CharField(
        label="Confirmation du mot de passe",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirmez le mot de passe'
        })
    )
    
    terms_accepted = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        label="J'accepte les conditions d'utilisation et la politique de confidentialité"
    )
    
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'password1', 'password2')
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Nom d\'utilisateur'
            })
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Appliquer les validateurs de mots de passe personnalisés
        self.validators = get_password_validators_from_settings()
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        
        if User.objects.filter(email=email).exists():
            raise ValidationError(_("Un compte avec cette adresse email existe déjà."))
        
        # Vérifier le domaine email si configuré
        allowed_domains = getattr(settings, 'ALLOWED_EMAIL_DOMAINS', None)
        if allowed_domains:
            domain = email.split('@')[1].lower()
            if domain not in allowed_domains:
                raise ValidationError(_("Cette adresse email n'est pas autorisée pour l'inscription."))
        
        return email
    
    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        
        # Appliquer les validateurs personnalisés
        for validator in self.validators:
            validator.validate(password, self.instance)
        
        return password
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        
        if commit:
            user.save()
            logger.info(f"Nouveau compte créé: {user.username} ({user.email})")
        
        return user


class PasswordResetRequestForm(forms.Form):
    """
    Formulaire de demande de réinitialisation de mot de passe
    Exigence: Réinitialisation sécurisée des mots de passe
    """
    
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Votre adresse email'
        }),
        label="Adresse email"
    )
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        
        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                raise ValidationError(_("Ce compte est désactivé."))
        except User.DoesNotExist:
            # Ne pas révéler si l'email existe ou non
            pass
        
        return email


class ProfileUpdateForm(forms.ModelForm):
    """
    Formulaire de mise à jour du profil utilisateur
    Exigence: Gestion des informations personnelles
    """
    
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'phone_number')
        widgets = {
            'first_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Prénom'
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Nom'
            }),
            'phone_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '+221 XX XXX XX XX'
            })
        }
    
    def clean_phone_number(self):
        phone = self.cleaned_data.get('phone_number')
        
        if phone:
            # Validation basique du format
            import re
            if not re.match(r'^\+?[1-9]\d{1,14}$', phone.replace(' ', '').replace('-', '')):
                raise ValidationError(_("Format de numéro de téléphone invalide."))
        
        return phone


class ChangePasswordForm(forms.Form):
    """
    Formulaire de changement de mot de passe
    Exigence: Changement sécurisé avec vérification de l'ancien mot de passe
    """
    
    current_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Mot de passe actuel'
        }),
        label="Mot de passe actuel"
    )
    
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nouveau mot de passe'
        }),
        label="Nouveau mot de passe"
    )
    
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirmez le nouveau mot de passe'
        }),
        label="Confirmation du nouveau mot de passe"
    )
    
    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.validators = get_password_validators_from_settings()
    
    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password')
        
        if not self.user.check_password(current_password):
            raise ValidationError(_("Mot de passe actuel incorrect."))
        
        return current_password
    
    def clean_new_password1(self):
        password = self.cleaned_data.get('new_password1')
        
        # Appliquer les validateurs
        for validator in self.validators:
            validator.validate(password, self.user)
        
        return password
    
    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get('new_password1')
        new_password2 = cleaned_data.get('new_password2')
        
        if new_password1 and new_password2:
            if new_password1 != new_password2:
                raise ValidationError(_("Les deux mots de passe ne correspondent pas."))
        
        return cleaned_data
    
    def save(self):
        """Sauvegarde le nouveau mot de passe"""
        new_password = self.cleaned_data['new_password1']
        
        # Ajouter à l'historique des mots de passe
        from .models import PasswordHistory
        PasswordHistory.add_password(self.user, new_password)
        
        # Changer le mot de passe
        self.user.set_password(new_password)
        self.user.last_password_change = timezone.now()
        self.user.save()
        
        logger.info(f"Mot de passe changé pour l'utilisateur {self.user.username}")


class DisableTwoFactorForm(forms.Form):
    """
    Formulaire pour désactiver l'authentification à deux facteurs
    Exigence: Désactivation sécurisée du 2FA
    """
    
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Votre mot de passe'
        }),
        label="Mot de passe de confirmation"
    )
    
    confirmation = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        label="Je comprends que désactiver l'authentification à deux facteurs réduit la sécurité de mon compte"
    )
    
    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
    
    def clean_password(self):
        password = self.cleaned_data.get('password')
        
        if not self.user.check_password(password):
            raise ValidationError(_("Mot de passe incorrect."))
        
        return password