# accounts/validators.py - Validateurs de mots de passe personnalisés pour GalSecVote
"""
Validateurs de mots de passe renforcés pour GalSecVote
Implémentation des exigences de sécurité des mots de passe
"""

import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from django.conf import settings


class CustomPasswordValidator:
    """
    Validateur de mot de passe personnalisé pour GalSecVote
    Exigence: Politique de mots de passe renforcée
    """
    
    def __init__(self, min_length=12, require_uppercase=True, require_lowercase=True, 
                 require_digits=True, require_special_chars=True, forbidden_patterns=None):
        """
        Initialise le validateur avec les règles de politique
        
        Args:
            min_length: Longueur minimale du mot de passe
            require_uppercase: Exiger au moins une majuscule
            require_lowercase: Exiger au moins une minuscule
            require_digits: Exiger au moins un chiffre
            require_special_chars: Exiger au moins un caractère spécial
            forbidden_patterns: Liste de motifs interdits
        """
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digits = require_digits
        self.require_special_chars = require_special_chars
        self.forbidden_patterns = forbidden_patterns or [
            'password', 'admin', 'user', 'galsecvote', 'vote', 'election'
        ]
        
        # Caractères spéciaux autorisés
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def validate(self, password, user=None):
        """
        Valide le mot de passe selon les règles définies
        
        Args:
            password: Mot de passe à valider
            user: Utilisateur (optionnel, pour vérifier la similarité)
            
        Raises:
            ValidationError: Si le mot de passe ne respecte pas les règles
        """
        errors = []
        
        # Vérifier la longueur minimale
        if len(password) < self.min_length:
            errors.append(
                ValidationError(
                    _("Le mot de passe doit contenir au moins %(min_length)d caractères."),
                    code='password_too_short',
                    params={'min_length': self.min_length},
                )
            )
        
        # Vérifier la présence de majuscules
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append(
                ValidationError(
                    _("Le mot de passe doit contenir au moins une lettre majuscule."),
                    code='password_no_uppercase',
                )
            )
        
        # Vérifier la présence de minuscules
        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append(
                ValidationError(
                    _("Le mot de passe doit contenir au moins une lettre minuscule."),
                    code='password_no_lowercase',
                )
            )
        
        # Vérifier la présence de chiffres
        if self.require_digits and not re.search(r'[0-9]', password):
            errors.append(
                ValidationError(
                    _("Le mot de passe doit contenir au moins un chiffre."),
                    code='password_no_digit',
                )
            )
        
        # Vérifier la présence de caractères spéciaux
        if self.require_special_chars and not re.search(f'[{re.escape(self.special_chars)}]', password):
            errors.append(
                ValidationError(
                    _("Le mot de passe doit contenir au moins un caractère spécial (%(special_chars)s)."),
                    code='password_no_special',
                    params={'special_chars': self.special_chars},
                )
            )
        
        # Vérifier les motifs interdits
        for pattern in self.forbidden_patterns:
            if pattern.lower() in password.lower():
                errors.append(
                    ValidationError(
                        _("Le mot de passe ne doit pas contenir le terme '%(pattern)s'."),
                        code='password_forbidden_pattern',
                        params={'pattern': pattern},
                    )
                )
        
        # Vérifier la similarité avec les informations utilisateur
        if user:
            self._validate_user_similarity(password, user, errors)
        
        # Vérifier les séquences communes
        self._validate_common_sequences(password, errors)
        
        if errors:
            raise ValidationError(errors)
    
    def _validate_user_similarity(self, password, user, errors):
        """Vérifie que le mot de passe n'est pas trop similaire aux infos utilisateur"""
        user_info = [
            user.username,
            user.email.split('@')[0] if user.email else '',
            user.first_name if hasattr(user, 'first_name') else '',
            user.last_name if hasattr(user, 'last_name') else '',
        ]
        
        for info in user_info:
            if info and len(info) >= 3 and info.lower() in password.lower():
                errors.append(
                    ValidationError(
                        _("Le mot de passe ne doit pas être trop similaire à vos informations personnelles."),
                        code='password_too_similar',
                    )
                )
                break
    
    def _validate_common_sequences(self, password, errors):
        """Vérifie les séquences communes dans le mot de passe"""
        # Séquences de clavier
        keyboard_sequences = [
            'qwerty', 'azerty', 'qwertz', '123456', 'abcdef',
            'qwer', 'asdf', 'zxcv', '1234', 'abcd'
        ]
        
        password_lower = password.lower()
        for sequence in keyboard_sequences:
            if sequence in password_lower:
                errors.append(
                    ValidationError(
                        _("Le mot de passe ne doit pas contenir de séquences communes du clavier."),
                        code='password_common_sequence',
                    )
                )
                break
        
        # Vérifier les répétitions de caractères
        if re.search(r'(.)\1{2,}', password):  # 3 caractères identiques consécutifs
            errors.append(
                ValidationError(
                    _("Le mot de passe ne doit pas contenir plus de 2 caractères identiques consécutifs."),
                    code='password_repeated_chars',
                )
            )
    
    def get_help_text(self):
        """Retourne le texte d'aide pour les règles de mot de passe"""
        help_texts = [
            f"Votre mot de passe doit contenir au moins {self.min_length} caractères."
        ]
        
        if self.require_uppercase:
            help_texts.append("Au moins une lettre majuscule.")
        
        if self.require_lowercase:
            help_texts.append("Au moins une lettre minuscule.")
        
        if self.require_digits:
            help_texts.append("Au moins un chiffre.")
        
        if self.require_special_chars:
            help_texts.append(f"Au moins un caractère spécial ({self.special_chars}).")
        
        help_texts.append("Ne doit pas contenir d'informations personnelles.")
        help_texts.append("Ne doit pas contenir de séquences communes.")
        
        return " ".join(help_texts)


class PasswordHistoryValidator:
    """
    Validateur pour empêcher la réutilisation des anciens mots de passe
    Exigence: Éviter la réutilisation des mots de passe récents
    """
    
    def __init__(self, password_history_count=5):
        """
        Initialise le validateur d'historique
        
        Args:
            password_history_count: Nombre de mots de passe à retenir
        """
        self.password_history_count = password_history_count
    
    def validate(self, password, user=None):
        """
        Valide que le mot de passe n'a pas été utilisé récemment
        
        Args:
            password: Nouveau mot de passe
            user: Utilisateur
            
        Raises:
            ValidationError: Si le mot de passe a été utilisé récemment
        """
        if not user or not user.pk:
            return  # Pas de validation pour les nouveaux utilisateurs
        
        try:
            from .models import PasswordHistory
            
            if PasswordHistory.is_password_reused(user, password):
                raise ValidationError(
                    _("Vous ne pouvez pas réutiliser un de vos %(count)d derniers mots de passe."),
                    code='password_reused',
                    params={'count': self.password_history_count},
                )
        except ImportError:
            # Le modèle PasswordHistory n'existe pas encore
            pass
    
    def get_help_text(self):
        """Retourne le texte d'aide"""
        return _(
            f"Votre mot de passe ne doit pas être identique à un de vos "
            f"{self.password_history_count} derniers mots de passe."
        )


class PasswordStrengthValidator:
    """
    Validateur de force du mot de passe basé sur l'entropie
    Exigence: Assurer une complexité suffisante
    """
    
    def __init__(self, min_entropy=50):
        """
        Initialise le validateur de force
        
        Args:
            min_entropy: Entropie minimale requise (bits)
        """
        self.min_entropy = min_entropy
    
    def validate(self, password, user=None):
        """
        Valide la force du mot de passe basée sur l'entropie
        
        Args:
            password: Mot de passe à valider
            user: Utilisateur (non utilisé)
            
        Raises:
            ValidationError: Si le mot de passe est trop faible
        """
        entropy = self.calculate_entropy(password)
        
        if entropy < self.min_entropy:
            raise ValidationError(
                _("Le mot de passe est trop faible. Force actuelle: %(current)d bits, "
                  "minimum requis: %(minimum)d bits."),
                code='password_too_weak',
                params={'current': int(entropy), 'minimum': self.min_entropy},
            )
    
    def calculate_entropy(self, password):
        """
        Calcule l'entropie approximative du mot de passe
        
        Args:
            password: Mot de passe
            
        Returns:
            float: Entropie en bits
        """
        import math
        
        # Compter les différents types de caractères
        char_sets = 0
        
        if re.search(r'[a-z]', password):
            char_sets += 26  # minuscules
        if re.search(r'[A-Z]', password):
            char_sets += 26  # majuscules
        if re.search(r'[0-9]', password):
            char_sets += 10  # chiffres
        if re.search(r'[^a-zA-Z0-9]', password):
            char_sets += 32  # caractères spéciaux (estimation)
        
        # Calculer l'entropie: log2(charset^length)
        if char_sets > 0:
            entropy = len(password) * math.log2(char_sets)
        else:
            entropy = 0
        
        return entropy
    
    def get_help_text(self):
        """Retourne le texte d'aide"""
        return _(
            f"Votre mot de passe doit avoir une complexité d'au moins "
            f"{self.min_entropy} bits d'entropie."
        )


def get_password_validators_from_settings():
    """
    Retourne les validateurs configurés selon les settings
    
    Returns:
        list: Liste des validateurs configurés
    """
    validators = []
    
    # Récupérer la configuration depuis les settings
    password_policy = getattr(settings, 'PASSWORD_POLICY', {})
    
    # Validateur principal
    validators.append(CustomPasswordValidator(
        min_length=password_policy.get('MIN_LENGTH', 12),
        require_uppercase=password_policy.get('REQUIRE_UPPERCASE', True),
        require_lowercase=password_policy.get('REQUIRE_LOWERCASE', True),
        require_digits=password_policy.get('REQUIRE_DIGITS', True),
        require_special_chars=password_policy.get('REQUIRE_SPECIAL_CHARS', True),
        forbidden_patterns=password_policy.get('FORBIDDEN_PATTERNS', None)
    ))
    
    # Validateur d'historique
    if password_policy.get('PASSWORD_HISTORY_COUNT', 0) > 0:
        validators.append(PasswordHistoryValidator(
            password_history_count=password_policy['PASSWORD_HISTORY_COUNT']
        ))
    
    # Validateur de force
    if password_policy.get('MIN_ENTROPY', 0) > 0:
        validators.append(PasswordStrengthValidator(
            min_entropy=password_policy['MIN_ENTROPY']
        ))
    
    return validators