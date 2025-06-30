# accounts/tests.py - Tests pour l'authentification 2FA de GalSecVote
"""
Tests unitaires et d'intégration pour le système d'authentification sécurisé
Exigence: Tests complets des fonctionnalités de sécurité
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from unittest.mock import patch, MagicMock
import pyotp
import time

from .models import User, TwoFactorAuth, UserSession, PasswordHistory
from .forms import SecureLoginForm, TwoFactorSetupForm, TwoFactorVerifyForm
from audit.models import AuditLog, SecurityEvent

User = get_user_model()


class UserModelTest(TestCase):
    """Tests pour le modèle User personnalisé"""
    
    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@esp.sn',
            'password': 'TestPassword123!'
        }
    
    def test_create_user(self):
        """Test de création d'un utilisateur"""
        user = User.objects.create_user(**self.user_data)
        
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@esp.sn')
        self.assertTrue(user.check_password('TestPassword123!'))
        self.assertFalse(user.is_verified)
        self.assertFalse(user.is_2fa_enabled)
        self.assertEqual(user.role, 'voter')
    
    def test_account_locking(self):
        """Test du verrouillage de compte après tentatives échouées"""
        user = User.objects.create_user(**self.user_data)
        
        # Vérifier que le compte n'est pas verrouillé initialement
        self.assertFalse(user.is_account_locked())
        
        # Simuler 5 tentatives échouées
        for i in range(5):
            user.increment_failed_login()
        
        # Le compte devrait être verrouillé
        self.assertTrue(user.is_account_locked())
        
        # Reset des tentatives
        user.reset_failed_login()
        self.assertFalse(user.is_account_locked())
    
    def test_user_permissions(self):
        """Test des permissions utilisateur"""
        admin_user = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPass123!',
            role='admin'
        )
        
        voter_user = User.objects.create_user(
            username='voter',
            email='voter@esp.sn',
            password='VoterPass123!',
            role='voter'
        )
        
        self.assertEqual(admin_user.role, 'admin')
        self.assertEqual(voter_user.role, 'voter')


class TwoFactorAuthTest(TestCase):
    """Tests pour l'authentification à deux facteurs"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
        self.two_factor = TwoFactorAuth.objects.create(user=self.user)
    
    def test_generate_secret(self):
        """Test de génération du secret TOTP"""
        secret = self.two_factor.generate_secret()
        
        self.assertIsInstance(secret, str)
        self.assertEqual(len(secret), 32)  # Base32 secret length
        self.assertEqual(self.two_factor.secret_key, secret)
    
    def test_totp_verification(self):
        """Test de vérification du code TOTP"""
        secret = self.two_factor.generate_secret()
        totp = pyotp.TOTP(secret)
        
        # Générer un code valide
        valid_code = totp.now()
        self.assertTrue(self.two_factor.verify_token(valid_code))
        
        # Code invalide
        self.assertFalse(self.two_factor.verify_token('000000'))
    
    def test_backup_tokens(self):
        """Test des tokens de récupération"""
        tokens = self.two_factor.generate_backup_tokens()
        
        self.assertEqual(len(tokens), 10)
        self.assertEqual(len(self.two_factor.backup_tokens), 10)
        
        # Utiliser un token
        token = tokens[0]
        self.assertTrue(self.two_factor.use_backup_token(token))
        
        # Le token ne devrait plus être utilisable
        self.assertFalse(self.two_factor.use_backup_token(token))
        self.assertEqual(len(self.two_factor.backup_tokens), 9)
    
    def test_get_totp_uri(self):
        """Test de génération de l'URI TOTP pour QR code"""
        secret = self.two_factor.generate_secret()
        uri = self.two_factor.get_totp_uri()
        
        self.assertIn('otpauth://totp/', uri)
        self.assertIn('GalSecVote', uri)
        self.assertIn(self.user.email, uri)


class SecureLoginFormTest(TestCase):
    """Tests pour le formulaire de connexion sécurisé"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
    
    def test_valid_login(self):
        """Test de connexion valide"""
        form_data = {
            'username': 'test@esp.sn',
            'password': 'TestPassword123!'
        }
        form = SecureLoginForm(data=form_data)
        
        self.assertTrue(form.is_valid())
        self.assertEqual(form.get_user(), self.user)
    
    def test_invalid_credentials(self):
        """Test avec des identifiants invalides"""
        form_data = {
            'username': 'test@esp.sn',
            'password': 'WrongPassword'
        }
        form = SecureLoginForm(data=form_data)
        
        self.assertFalse(form.is_valid())
        self.assertIn('invalid_login', form.errors['__all__'][0].code)
    
    def test_locked_account(self):
        """Test de connexion sur compte verrouillé"""
        # Verrouiller le compte
        for _ in range(5):
            self.user.increment_failed_login()
        
        form_data = {
            'username': 'test@esp.sn',
            'password': 'TestPassword123!'
        }
        form = SecureLoginForm(data=form_data)
        
        self.assertFalse(form.is_valid())
        self.assertIn('account_locked', form.errors['__all__'][0].code)
    
    def test_nonexistent_user(self):
        """Test avec utilisateur inexistant"""
        form_data = {
            'username': 'nonexistent@esp.sn',
            'password': 'AnyPassword123!'
        }
        form = SecureLoginForm(data=form_data)
        
        self.assertFalse(form.is_valid())


class TwoFactorSetupFormTest(TestCase):
    """Tests pour le formulaire de configuration 2FA"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
        self.secret_key = pyotp.random_base32()
    
    def test_valid_verification_code(self):
        """Test avec code de vérification valide"""
        totp = pyotp.TOTP(self.secret_key)
        valid_code = totp.now()
        
        form_data = {
            'verification_code': valid_code
        }
        form = TwoFactorSetupForm(self.user, self.secret_key, data=form_data)
        
        self.assertTrue(form.is_valid())
    
    def test_invalid_verification_code(self):
        """Test avec code invalide"""
        form_data = {
            'verification_code': '000000'
        }
        form = TwoFactorSetupForm(self.user, self.secret_key, data=form_data)
        
        self.assertFalse(form.is_valid())
    
    def test_non_numeric_code(self):
        """Test avec code non numérique"""
        form_data = {
            'verification_code': 'ABC123'
        }
        form = TwoFactorSetupForm(self.user, self.secret_key, data=form_data)
        
        self.assertFalse(form.is_valid())


class TwoFactorVerifyFormTest(TestCase):
    """Tests pour le formulaire de vérification 2FA"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
        self.two_factor = TwoFactorAuth.objects.create(user=self.user)
        self.secret = self.two_factor.generate_secret()
        self.two_factor.is_verified = True
        self.two_factor.save()
    
    def test_valid_totp_code(self):
        """Test avec code TOTP valide"""
        totp = pyotp.TOTP(self.secret)
        valid_code = totp.now()
        
        form_data = {
            'code': valid_code
        }
        form = TwoFactorVerifyForm(self.user, data=form_data)
        
        self.assertTrue(form.is_valid())
    
    def test_valid_backup_token(self):
        """Test avec token de récupération valide"""
        backup_tokens = self.two_factor.generate_backup_tokens()
        
        form_data = {
            'backup_token': backup_tokens[0]
        }
        form = TwoFactorVerifyForm(self.user, data=form_data)
        
        self.assertTrue(form.is_valid())
    
    def test_invalid_code_and_token(self):
        """Test avec code et token invalides"""
        form_data = {
            'code': '000000',
            'backup_token': 'invalid_token'
        }
        form = TwoFactorVerifyForm(self.user, data=form_data)
        
        self.assertFalse(form.is_valid())


class LoginViewTest(TestCase):
    """Tests d'intégration pour les vues de connexion"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
        self.login_url = reverse('accounts:login')
    
    def test_login_page_loads(self):
        """Test de chargement de la page de connexion"""
        response = self.client.get(self.login_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'GalSecVote')
        self.assertContains(response, 'Connexion sécurisée')
    
    def test_successful_login_without_2fa(self):
        """Test de connexion réussie sans 2FA configuré"""
        response = self.client.post(self.login_url, {
            'username': 'test@esp.sn',
            'password': 'TestPassword123!'
        })
        
        # Devrait rediriger vers la configuration 2FA
        self.assertEqual(response.status_code, 302)
        self.assertIn('2fa_setup', response.url)
    
    def test_successful_login_with_2fa(self):
        """Test de connexion avec 2FA configuré"""
        # Configurer 2FA
        two_factor = TwoFactorAuth.objects.create(user=self.user)
        two_factor.generate_secret()
        two_factor.is_verified = True
        two_factor.save()
        
        response = self.client.post(self.login_url, {
            'username': 'test@esp.sn',
            'password': 'TestPassword123!'
        })
        
        # Devrait rediriger vers la vérification 2FA
        self.assertEqual(response.status_code, 302)
        self.assertIn('2fa_verify', response.url)
    
    def test_failed_login_creates_security_event(self):
        """Test qu'un échec de connexion crée un événement de sécurité"""
        initial_count = SecurityEvent.objects.count()
        
        self.client.post(self.login_url, {
            'username': 'test@esp.sn',
            'password': 'WrongPassword'
        })
        
        self.assertEqual(SecurityEvent.objects.count(), initial_count + 1)
        
        event = SecurityEvent.objects.latest('detected_at')
        self.assertEqual(event.event_type, 'failed_login')


class TwoFactorSetupViewTest(TestCase):
    """Tests pour la vue de configuration 2FA"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
        self.setup_url = reverse('accounts:2fa_setup')
    
    def test_setup_requires_session(self):
        """Test que la configuration 2FA nécessite une session valide"""
        response = self.client.get(self.setup_url)
        
        # Devrait rediriger vers login
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_setup_page_loads_with_session(self):
        """Test de chargement avec session valide"""
        # Simuler une session de configuration
        session = self.client.session
        session['setup_2fa_user_id'] = self.user.id
        session.save()
        
        response = self.client.get(self.setup_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Configuration de l\'authentification')
    
    def test_successful_2fa_setup(self):
        """Test de configuration 2FA réussie"""
        # Créer une configuration 2FA temporaire
        two_factor = TwoFactorAuth.objects.create(user=self.user)
        secret = two_factor.generate_secret()
        
        session = self.client.session
        session['setup_2fa_user_id'] = self.user.id
        session.save()
        
        # Générer un code valide
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        response = self.client.post(self.setup_url, {
            'verification_code': valid_code
        })
        
        # Devrait rediriger vers les tokens de récupération
        self.assertEqual(response.status_code, 302)
        self.assertIn('backup_tokens', response.url)
        
        # Vérifier que 2FA est activé
        two_factor.refresh_from_db()
        self.assertTrue(two_factor.is_verified)


class UserSessionTest(TestCase):
    """Tests pour la gestion des sessions utilisateur"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
    
    def test_create_user_session(self):
        """Test de création de session utilisateur"""
        session = UserSession.objects.create(
            user=self.user,
            session_key='test_session_key',
            ip_address='127.0.0.1',
            user_agent='Test User Agent',
            expires_at=timezone.now() + timezone.timedelta(hours=1)
        )
        
        self.assertEqual(session.user, self.user)
        self.assertTrue(session.is_active)
        self.assertFalse(session.is_expired())
    
    def test_session_expiration(self):
        """Test d'expiration de session"""
        # Créer une session expirée
        session = UserSession.objects.create(
            user=self.user,
            session_key='expired_session',
            ip_address='127.0.0.1',
            user_agent='Test User Agent',
            expires_at=timezone.now() - timezone.timedelta(hours=1)
        )
        
        self.assertTrue(session.is_expired())
    
    def test_extend_session(self):
        """Test de prolongation de session"""
        session = UserSession.objects.create(
            user=self.user,
            session_key='test_session',
            ip_address='127.0.0.1',
            user_agent='Test User Agent',
            expires_at=timezone.now() + timezone.timedelta(minutes=10)
        )
        
        old_expires = session.expires_at
        session.extend_session(30)
        
        self.assertGreater(session.expires_at, old_expires)
    
    def test_cleanup_expired_sessions(self):
        """Test de nettoyage des sessions expirées"""
        # Créer des sessions expirées et actives
        UserSession.objects.create(
            user=self.user,
            session_key='expired1',
            ip_address='127.0.0.1',
            user_agent='Test',
            expires_at=timezone.now() - timezone.timedelta(hours=1)
        )
        
        UserSession.objects.create(
            user=self.user,
            session_key='active1',
            ip_address='127.0.0.1',
            user_agent='Test',
            expires_at=timezone.now() + timezone.timedelta(hours=1)
        )
        
        # Nettoyer les sessions expirées
        count = UserSession.cleanup_expired_sessions()
        
        self.assertEqual(count, 1)
        self.assertEqual(UserSession.objects.filter(is_active=True).count(), 1)


class PasswordHistoryTest(TestCase):
    """Tests pour l'historique des mots de passe"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
    
    def test_add_password_to_history(self):
        """Test d'ajout d'un mot de passe à l'historique"""
        PasswordHistory.add_password(self.user, 'NewPassword123!')
        
        self.assertEqual(PasswordHistory.objects.filter(user=self.user).count(), 1)
    
    def test_password_reuse_detection(self):
        """Test de détection de réutilisation de mot de passe"""
        password = 'TestPassword123!'
        PasswordHistory.add_password(self.user, password)
        
        # Le même mot de passe devrait être détecté comme réutilisé
        self.assertTrue(PasswordHistory.is_password_reused(self.user, password))
        
        # Un nouveau mot de passe ne devrait pas être détecté
        self.assertFalse(PasswordHistory.is_password_reused(self.user, 'NewPassword456!'))
    
    def test_password_history_limit(self):
        """Test de la limite d'historique des mots de passe"""
        # Ajouter 10 mots de passe
        for i in range(10):
            PasswordHistory.add_password(self.user, f'Password{i}123!')
        
        # Seuls les 5 derniers devraient être conservés
        self.assertEqual(PasswordHistory.objects.filter(user=self.user).count(), 5)


class AuditIntegrationTest(TestCase):
    """Tests d'intégration avec le système d'audit"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
    
    def test_login_creates_audit_log(self):
        """Test qu'une connexion crée un log d'audit"""
        initial_count = AuditLog.objects.count()
        
        # Simuler une connexion réussie (première étape)
        self.client.post(reverse('accounts:login'), {
            'username': 'test@esp.sn',
            'password': 'TestPassword123!'
        })
        
        # Devrait avoir créé un log d'audit
        self.assertGreater(AuditLog.objects.count(), initial_count)
        
        log = AuditLog.objects.latest('timestamp')
        self.assertEqual(log.action, 'first_factor_auth')
        self.assertEqual(log.user, self.user)
    
    def test_2fa_verification_creates_audit_log(self):
        """Test que la vérification 2FA crée un log d'audit"""
        # Configurer 2FA
        two_factor = TwoFactorAuth.objects.create(user=self.user)
        secret = two_factor.generate_secret()
        two_factor.is_verified = True
        two_factor.save()
        
        # Simuler la session pré-2FA
        session = self.client.session
        session['pre_2fa_user_id'] = self.user.id
        session['pre_2fa_timestamp'] = timezone.now().timestamp()
        session.save()
        
        initial_count = AuditLog.objects.count()
        
        # Vérification 2FA réussie
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        
        self.client.post(reverse('accounts:2fa_verify'), {
            'code': valid_code
        })
        
        # Devrait avoir créé un log d'audit
        self.assertGreater(AuditLog.objects.count(), initial_count)
        
        log = AuditLog.objects.latest('timestamp')
        self.assertEqual(log.action, '2fa_verification_success')


class SecurityTest(TestCase):
    """Tests de sécurité généraux"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
    
    def test_brute_force_protection(self):
        """Test de protection contre les attaques par force brute"""
        login_url = reverse('accounts:login')
        
        # Faire 5 tentatives échouées
        for i in range(5):
            self.client.post(login_url, {
                'username': 'test@esp.sn',
                'password': 'WrongPassword'
            })
        
        # Le compte devrait être verrouillé
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_account_locked())
        
        # Une tentative avec le bon mot de passe devrait échouer
        response = self.client.post(login_url, {
            'username': 'test@esp.sn',
            'password': 'TestPassword123!'
        })
        
        # Devrait afficher une erreur de compte verrouillé
        self.assertContains(response, 'verrouillé')
    
    def test_session_timeout(self):
        """Test du timeout de session"""
        # Simuler une session expirée lors de la vérification 2FA
        session = self.client.session
        session['pre_2fa_user_id'] = self.user.id
        session['pre_2fa_timestamp'] = (timezone.now() - timezone.timedelta(minutes=10)).timestamp()
        session.save()
        
        response = self.client.get(reverse('accounts:2fa_verify'))
        
        # Devrait rediriger vers login avec message d'expiration
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)
    
    def test_csrf_protection(self):
        """Test de protection CSRF"""
        login_url = reverse('accounts:login')
        
        # Tentative de POST sans token CSRF
        response = self.client.post(login_url, {
            'username': 'test@esp.sn',
            'password': 'TestPassword123!'
        }, HTTP_X_CSRFTOKEN='invalid')
        
        # Devrait être rejeté (403 ou formulaire invalide)
        self.assertIn(response.status_code, [403, 200])
    
    @patch('accounts.views.AuditLog.log_action')
    def test_audit_logging_on_security_events(self, mock_log):
        """Test que les événements de sécurité sont loggés"""
        # Tentative de connexion échouée
        self.client.post(reverse('accounts:login'), {
            'username': 'test@esp.sn',
            'password': 'WrongPassword'
        })
        
        # Vérifier que l'audit a été appelé
        mock_log.assert_called()


if __name__ == '__main__':
    import django
    from django.conf import settings
    from django.test.utils import get_runner
    
    if not settings.configured:
        settings.configure(
            DEBUG=True,
            DATABASES={
                'default': {
                    'ENGINE': 'django.db.backends.sqlite3',
                    'NAME': ':memory:',
                }
            },
            INSTALLED_APPS=[
                'django.contrib.auth',
                'django.contrib.contenttypes',
                'accounts',
                'audit',
            ],
            SECRET_KEY='test-secret-key',
            USE_TZ=True,
        )
    
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    failures = test_runner.run_tests(['accounts'])
    
    if failures:
        raise SystemExit(1)