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
from django.contrib.auth.password_validation import validate_password
import pyotp
import qrcode
import io
import base64
from .models import User, TwoFactorAuth
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
                if hasattr(user, 'is_account_locked') and user.is_account_locked():
                    logger.warning(f"Tentative de connexion sur compte verrouillé: {username}")
                    raise ValidationError(
                        _("Votre compte est temporairement verrouillé en raison de trop nombreuses tentatives de connexion. Veuillez réessayer plus tard."),
                        code='account_locked'
                    )
                
                # Authentifier l'utilisateur
                self.user_cache = authenticate(
                    self.request,
                    username=user.username,
                    password=password
                )
                
                if self.user_cache is None:
                    # Incrémenter le compteur d'échecs
                    if hasattr(user, 'increment_failed_login'):
                        user.increment_failed_login()
                    
                    logger.warning(f"Échec d'authentification pour: {username}")
                    raise ValidationError(
                        _("Nom d'utilisateur ou mot de passe incorrect."),
                        code='invalid_login'
                    )
                else:
                    # Reset du compteur d'échecs en cas de succès
                    if hasattr(user, 'reset_failed_login'):
                        user.reset_failed_login()
                
            except User.DoesNotExist:
                # Simuler un délai pour éviter l'énumération d'utilisateurs
                logger.warning(f"Tentative de connexion avec utilisateur inexistant: {username}")
                raise ValidationError(
                    _("Nom d'utilisateur ou mot de passe incorrect."),
                    code='invalid_login'
                )
        
        return self.cleaned_data


class TwoFactorSetupForm(forms.Form):
    """
    Formulaire de configuration de l'authentification à deux facteurs
    Exigence: Configuration 2FA obligatoire
    """
    
    verification_code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-control text-center',
            'placeholder': '000000',
            'pattern': '[0-9]{6}',
            'autocomplete': 'off',
            'inputmode': 'numeric'
        }),
        label="Code de vérification",
        help_text="Saisissez le code à 6 chiffres affiché dans votre application d'authentification"
    )
    
    def __init__(self, user=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.secret_key = pyotp.random_base32()
    
    def get_qr_code(self):
        """Génère le QR code pour la configuration"""
        if not self.user:
            return None
        
        totp_uri = pyotp.totp.TOTP(self.secret_key).provisioning_uri(
            name=self.user.email,
            issuer_name="GalSecVote"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def clean_verification_code(self):
        code = self.cleaned_data.get('verification_code')
        
        if code:
            totp = pyotp.TOTP(self.secret_key)
            if not totp.verify(code, valid_window=1):
                raise ValidationError(_("Code de vérification invalide."))
        
        return code


class TwoFactorVerifyForm(forms.Form):
    """
    Formulaire de vérification 2FA lors de la connexion
    Exigence: Vérification du second facteur
    """
    
    verification_code = forms.CharField(
        max_length=6,
        min_length=6,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control text-center',
            'placeholder': '000000',
            'pattern': '[0-9]{6}',
            'autocomplete': 'off',
            'inputmode': 'numeric'
        }),
        label="Code d'authentification"
    )
    
    backup_token = forms.CharField(
        max_length=8,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Token de récupération',
            'autocomplete': 'off'
        }),
        label="Token de récupération (optionnel)"
    )
    
    def __init__(self, user=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
    
    def clean(self):
        cleaned_data = super().clean()
        code = cleaned_data.get('verification_code')
        backup_token = cleaned_data.get('backup_token')
        
        if not code and not backup_token:
            raise ValidationError(_("Veuillez saisir un code d'authentification ou un token de récupération."))
        
        if not self.user:
            raise ValidationError(_("Session expirée. Veuillez vous reconnecter."))
        
        try:
            two_factor = self.user.two_factor
        except:
            raise ValidationError(_("Authentification à deux facteurs non configurée."))
        
        # Vérifier le code TOTP ou le token de récupération
        if code:
            if not two_factor.verify_token(code):
                logger.warning(f"Code 2FA invalide pour {self.user.username}")
                raise ValidationError(_("Code d'authentification invalide."))
        elif backup_token:
            if not hasattr(two_factor, 'use_backup_token') or not two_factor.use_backup_token(backup_token):
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
    
    accept_terms = forms.BooleanField(
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
        
        # Valider le mot de passe avec les validateurs Django
        if password:
            validate_password(password, self.instance)
        
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
            # Ne pas révéler si l'email existe ou non pour des raisons de sécurité
            pass
        
        return email


class ProfileUpdateForm(forms.ModelForm):
    """
    Formulaire de mise à jour du profil utilisateur
    """
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        
        # Vérifier que l'email n'est pas déjà utilisé par un autre utilisateur
        if User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise ValidationError(_("Cette adresse email est déjà utilisée."))
        
        return email


class ChangePasswordForm(forms.Form):
    """
    Formulaire de changement de mot de passe
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
    
    def __init__(self, user=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
    
    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password')
        
        if not self.user.check_password(current_password):
            raise ValidationError(_("Le mot de passe actuel est incorrect."))
        
        return current_password
    
    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        
        if password1 and password2 and password1 != password2:
            raise ValidationError(_("Les deux mots de passe ne correspondent pas."))
        
        # Valider le nouveau mot de passe
        if password2:
            validate_password(password2, self.user)
        
        return password2


class DisableTwoFactorForm(forms.Form):
    """
    Formulaire de désactivation de l'authentification à deux facteurs
    """
    
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Votre mot de passe'
        }),
        label="Mot de passe",
        help_text="Confirmez votre mot de passe pour désactiver la 2FA"
    )
    
    confirmation = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Tapez "DESACTIVER" pour confirmer'
        }),
        label="Confirmation"
    )
    
    def __init__(self, user=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
    
    def clean_password(self):
        password = self.cleaned_data.get('password')
        
        if not self.user.check_password(password):
            raise ValidationError(_("Mot de passe incorrect."))
        
        return password
    
    def clean_confirmation(self):
        confirmation = self.cleaned_data.get('confirmation')
        
        if confirmation != 'DESACTIVER':
            raise ValidationError(_('Vous devez taper "DESACTIVER" pour confirmer.'))
        
        return confirmation