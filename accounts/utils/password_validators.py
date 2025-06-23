"""
Validateurs de mots de passe personnalisés pour GalSecVote
Implémentation des exigences de politique de mots de passe renforcée
"""

import re
import hashlib
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from django.conf import settings
import logging

logger = logging.getLogger('accounts')


class CustomPasswordValidator:
    """
    Validateur de mot de passe personnalisé avec règles de sécurité renforcées
    Exigence: Politique de mots de passe forte
    """
    
    def _init_(self):
        """Initialise le validateur avec les paramètres de sécurité"""
        self.min_length = getattr(settings, 'PASSWORD_MIN_LENGTH', 12)
        self.max_length = getattr(settings, 'PASSWORD_MAX_LENGTH', 128)
        self.require_uppercase = getattr(settings, 'PASSWORD_REQUIRE_UPPERCASE', True)
        self.require_lowercase = getattr(settings, 'PASSWORD_REQUIRE_LOWERCASE', True)
        self.require_digits = getattr(settings, 'PASSWORD_REQUIRE_DIGITS', True)
        self.require_special_chars = getattr(settings, 'PASSWORD_REQUIRE_SPECIAL_CHARS', True)
        self.forbidden_patterns = getattr(settings, 'PASSWORD_FORBIDDEN_PATTERNS', [
            'password', 'admin', 'user', 'galsecvote', 'vote', 'election'
        ])
        
        # Caractères spéciaux autorisés
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def validate(self, password, user=None):
        """
        Valide un mot de passe selon les règles de sécurité
        
        Args:
            password: Mot de passe à valider
            user: Utilisateur (optionnel)
            
        Raises:
            ValidationError: Si le mot de passe ne respecte pas les règles
        """
        errors = []
        
        # Vérifier la longueur
        if len(password) < self.min_length:
            errors.append(_(f"Le mot de passe doit contenir au moins {self.min_length} caractères."))
        
        if len(password) > self.max_length:
            errors.append(_(f"Le mot de passe ne peut pas dépasser {self.max_length} caractères."))
        
        # Vérifier la présence de majuscules
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append(_("Le mot de passe doit contenir au moins une lettre majuscule."))
        
        # Vérifier la présence de minuscules
        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append(_("Le mot de passe doit contenir au moins une lettre minuscule."))
        
        # Vérifier la présence de chiffres
        if self.require_digits and not re.search(r'\d', password):
            errors.append(_("Le mot de passe doit contenir au moins un chiffre."))
        
        # Vérifier la présence de caractères spéciaux
        if self.require_special_chars and not re.search(f'[{re.escape(self.special_chars)}]', password):
            errors.append(("Le mot de passe doit contenir au moins un caractère spécial (!@#$%^&*()+-=[]{}|;:,.<>?)."))
        
        # Vérifier les motifs interdits
        password_lower = password.lower()
        for pattern in self.forbidden_patterns:
            if pattern.lower() in password_lower:
                errors.append(_(f"Le mot de passe ne peut pas contenir '{pattern}'."))
        
        # Vérifier la similarité avec les informations utilisateur
        if user:
            self._check_user_similarity(password, user, errors)
        
        # Vérifier les séquences communes
        self._check_common_sequences(password, errors)
        
        # Vérifier la complexité
        self._check_complexity(password, errors)
        
        if errors:
            logger.warning(f"Mot de passe rejeté pour l'utilisateur {user.username if user else 'anonyme'}: {len(errors)} erreurs")
            raise ValidationError(errors)
        
        logger.info(f"Mot de passe validé avec succès pour l'utilisateur {user.username if user else 'anonyme'}")
    
    def _check_user_similarity(self, password, user, errors):
        """Vérifie la similarité avec les informations utilisateur"""
        password_lower = password.lower()
        
        # Vérifier le nom d'utilisateur
        if user.username and len(user.username) >= 3:
            if user.username.lower() in password_lower:
                errors.append(_("Le mot de passe ne peut pas contenir votre nom d'utilisateur."))
        
        # Vérifier l'email
        if user.email:
            email_parts = user.email.lower().split('@')
            if email_parts[0] and len(email_parts[0]) >= 3:
                if email_parts[0] in password_lower:
                    errors.append(_("Le mot de passe ne peut pas contenir votre adresse email."))
        
        # Vérifier le prénom et nom (si disponibles dans le profil)
        if hasattr(user, 'profile'):
            if user.profile.first_name and len(user.profile.first_name) >= 3:
                if user.profile.first_name.lower() in password_lower:
                    errors.append(_("Le mot de passe ne peut pas contenir votre prénom."))
            
            if user.profile.last_name and len(user.profile.last_name) >= 3:
                if user.profile.last_name.lower() in password_lower:
                    errors.append(_("Le mot de passe ne peut pas contenir votre nom de famille."))
    
    def _check_common_sequences(self, password, errors):
        """Vérifie les séquences communes dangereuses"""
        # Séquences de clavier
        keyboard_sequences = [
            'qwerty', 'azerty', 'qwertz', 'asdf', 'zxcv',
            '123456', '987654', 'abcdef', 'fedcba'
        ]
        
        password_lower = password.lower()
        for sequence in keyboard_sequences:
            if sequence in password_lower:
                errors.append(_("Le mot de passe ne peut pas contenir de séquences communes de clavier."))
                break
        
        # Séquences répétitives
        if re.search(r'(.)\1{2,}', password):
            errors.append(_("Le mot de passe ne peut pas contenir plus de 2 caractères identiques consécutifs."))
        
        # Séquences numériques simples
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            errors.append(_("Le mot de passe ne peut pas contenir de séquences numériques simples."))
    
    def _check_complexity(self, password, errors):
        """Vérifie la complexité globale du mot de passe"""
        # Calculer le score de complexité
        complexity_score = 0
        
        # Points pour la variété des caractères
        if re.search(r'[a-z]', password):
            complexity_score += 1
        if re.search(r'[A-Z]', password):
            complexity_score += 1
        if re.search(r'\d', password):
            complexity_score += 1
        if re.search(f'[{re.escape(self.special_chars)}]', password):
            complexity_score += 1
        
        # Points pour la longueur
        if len(password) >= 16:
            complexity_score += 2
        elif len(password) >= 12:
            complexity_score += 1
        
        # Points pour la variété (pas de répétitions excessives)
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.7:  # 70% de caractères uniques
            complexity_score += 1
        
        # Score minimum requis
        min_complexity = 4
        if complexity_score < min_complexity:
            errors.append(_("Le mot de passe n'est pas assez complexe. Utilisez une combinaison variée de lettres, chiffres et caractères spéciaux."))
    
    def get_help_text(self):
        """Retourne le texte d'aide pour les exigences de mot de passe"""
        help_texts = [
            f"Votre mot de passe doit contenir entre {self.min_length} et {self.max_length} caractères."
        ]
        
        if self.require_uppercase:
            help_texts.append("Au moins une lettre majuscule.")
        if self.require_lowercase:
            help_texts.append("Au moins une lettre minuscule.")
        if self.require_digits:
            help_texts.append("Au moins un chiffre.")
        if self.require_special_chars:
            help_texts.append("Au moins un caractère spécial (!@#$%^&*()_+-=[]{}|;:,.<>?).")
        
        help_texts.append("Évitez les mots communs, séquences de clavier et informations personnelles.")
        
        return " ".join(help_texts)


class PasswordHistoryValidator:
    """
    Validateur pour éviter la réutilisation de mots de passe
    Exigence: Historique des mots de passe
    """
    
    def _init_(self, history_count=5):
        """
        Initialise le validateur d'historique
        
        Args:
            history_count: Nombre de mots de passe précédents à vérifier
        """
        self.history_count = history_count
    
    def validate(self, password, user=None):
        """
        Vérifie que le mot de passe n'a pas été utilisé récemment
        
        Args:
            password: Nouveau mot de passe
            user: Utilisateur
            
        Raises:
            ValidationError: Si le mot de passe a été utilisé récemment
        """
        if not user or not user.pk:
            return  # Pas de vérification pour les nouveaux utilisateurs
        
        try:
            from accounts.models import PasswordHistory
            
            # Vérifier si le mot de passe a été utilisé
            if PasswordHistory.is_password_reused(user, password):
                logger.warning(f"Tentative de réutilisation de mot de passe pour {user.username}")
                raise ValidationError(
                    _(f"Vous ne pouvez pas réutiliser l'un de vos {self.history_count} derniers mots de passe."),
                    code='password_reused'
                )
        
        except ImportError:
            # Si le modèle PasswordHistory n'existe pas encore
            pass
    
    def get_help_text(self):
        """Retourne le texte d'aide pour l'historique des mots de passe"""
        return _(f"Votre mot de passe ne peut pas être identique à l'un de vos {self.history_count} derniers mots de passe.")


class CommonPasswordValidator:
    """
    Validateur pour éviter les mots de passe les plus communs
    Exigence: Protection contre les mots de passe faibles
    """
    
    def _init_(self):
        """Initialise le validateur avec une liste de mots de passe communs"""
        self.common_passwords = {
            'password', 'password123', '123456', '123456789', 'qwerty',
            'abc123', 'password1', '12345678', '111111', '1234567890',
            'admin', 'administrator', 'root', 'user', 'guest', 'test',
            'azerty', 'motdepasse', 'mdp123', 'admin123', 'user123',
            'galsecvote', 'vote123', 'election', 'scrutin', 'bulletin'
        }
    
    def validate(self, password, user=None):
        """
        Vérifie que le mot de passe n'est pas dans la liste des mots de passe communs
        
        Args:
            password: Mot de passe à vérifier
            user: Utilisateur (optionnel)
            
        Raises:
            ValidationError: Si le mot de passe est trop commun
        """
        password_lower = password.lower()
        
        if password_lower in self.common_passwords:
            logger.warning(f"Mot de passe commun détecté pour {user.username if user else 'anonyme'}")
            raise ValidationError(
                _("Ce mot de passe est trop commun. Choisissez un mot de passe plus original."),
                code='password_too_common'
            )
    
    def get_help_text(self):
        """Retourne le texte d'aide pour les mots de passe communs"""
        return _("Votre mot de passe ne peut pas être un mot de passe couramment utilisé.")


class PasswordStrengthValidator:
    """
    Validateur de force de mot de passe avec score
    Exigence: Évaluation de la robustesse
    """
    
    def _init_(self, min_strength=3):
        """
        Initialise le validateur de force
        
        Args:
            min_strength: Force minimale requise (1-5)
        """
        self.min_strength = min_strength
    
    def calculate_strength(self, password):
        """
        Calcule la force d'un mot de passe (score 1-5)
        
        Args:
            password: Mot de passe à évaluer
            
        Returns:
            int: Score de force (1=très faible, 5=très fort)
        """
        score = 0
        
        # Longueur
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        
        # Variété des caractères
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            score += 1
        
        # Bonus pour la complexité
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.8:
            score += 1
        
        # Pénalité pour les patterns
        if re.search(r'(.)\1{2,}', password):  # Répétitions
            score -= 1
        if re.search(r'(abc|123|qwe)', password.lower()):  # Séquences
            score -= 1
        
        return max(1, min(5, score))
    
    def validate(self, password, user=None):
        """
        Valide la force du mot de passe
        
        Args:
            password: Mot de passe à valider
            user: Utilisateur (optionnel)
            
        Raises:
            ValidationError: Si le mot de passe n'est pas assez fort
        """
        strength = self.calculate_strength(password)
        
        if strength < self.min_strength:
            strength_labels = {
                1: "très faible",
                2: "faible",
                3: "moyenne",
                4: "forte",
                5: "très forte"
            }
            
            logger.warning(f"Mot de passe de force insuffisante ({strength}/{self.min_strength}) pour {user.username if user else 'anonyme'}")
            
            raise ValidationError(
                _(f"Ce mot de passe est de force {strength_labels[strength]}. "
                  f"Utilisez un mot de passe de force {strength_labels[self.min_strength]} ou plus."),
                code='password_too_weak'
            )
    
    def get_help_text(self):
        """Retourne le texte d'aide pour la force des mots de passe"""
        return _(f"Votre mot de passe doit avoir une force minimale de {self.min_strength}/5. "
                "Utilisez une combinaison de lettres majuscules et minuscules, chiffres et caractères spéciaux.")


# Fonctions utilitaires pour les tests de mot de passe

def test_password_strength(password):
    """
    Teste la force d'un mot de passe et retourne des détails
    
    Args:
        password: Mot de passe à tester
        
    Returns:
        dict: Détails sur la force du mot de passe
    """
    validator = PasswordStrengthValidator()
    strength = validator.calculate_strength(password)
    
    details = {
        'strength': strength,
        'length': len(password),
        'has_uppercase': bool(re.search(r'[A-Z]', password)),
        'has_lowercase': bool(re.search(r'[a-z]', password)),
        'has_digits': bool(re.search(r'\d', password)),
        'has_special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password)),
        'unique_chars': len(set(password)),
        'has_repetitions': bool(re.search(r'(.)\1{2,}', password)),
        'has_sequences': bool(re.search(r'(abc|123|qwe)', password.lower()))
    }
    
    return details


def generate_password_suggestions(length=16):
    """
    Génère des suggestions de mots de passe forts
    
    Args:
        length: Longueur souhaitée
        
    Returns:
        list: Liste de mots de passe suggérés
    """
    import secrets
    import string
    
    suggestions = []
    
    for _ in range(3):
        # Créer un mot de passe avec tous les types de caractères
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        # S'assurer qu'il contient tous les types requis
        if (re.search(r'[a-z]', password) and 
            re.search(r'[A-Z]', password) and 
            re.search(r'\d', password) and 
            re.search(r'[!@#$%^&*()_+\-=]', password)):
            suggestions.append(password)
    
    return suggestions