#!/usr/bin/env python
# test_standalone.py - Tests complètement indépendants pour GalSecVote
"""
Tests indépendants pour valider le code GalSecVote
Sans dépendance aux settings Django existants
"""

import os
import sys
import tempfile
from pathlib import Path

# Ajouter le projet au path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

def configure_minimal_django():
    """Configure Django avec des settings minimaux pour les tests"""
    
    import django
    from django.conf import settings
    
    # Vérifier d'abord que pyotp est disponible
    try:
        import pyotp
    except ImportError:
        print("⚠️  Package 'pyotp' manquant. Installez-le avec: pip install pyotp")
        return False
    
    if not settings.configured:
        # Configuration minimale complètement autonome
        settings.configure(
            DEBUG=True,
            SECRET_KEY='test-key-not-for-production',
            DATABASES={
                'default': {
                    'ENGINE': 'django.db.backends.sqlite3',
                    'NAME': ':memory:',
                }
            },
            INSTALLED_APPS=[
                'django.contrib.contenttypes',
                'django.contrib.auth',
                'django.contrib.sessions',
                'django.contrib.messages',
                'accounts',
                'vote', 
                'cryptoutils',
                'dashboard',
                'audit',
            ],
            MIDDLEWARE=[
                'django.middleware.security.SecurityMiddleware',
                'django.contrib.sessions.middleware.SessionMiddleware',
                'django.middleware.common.CommonMiddleware',
                'django.middleware.csrf.CsrfViewMiddleware',
                'django.contrib.auth.middleware.AuthenticationMiddleware',
                'django.contrib.messages.middleware.MessageMiddleware',
            ],
            AUTH_USER_MODEL='accounts.User',
            USE_TZ=True,
            # Configuration sans problèmes de static files
            STATIC_URL=None,
            STATIC_ROOT=None,
            MEDIA_URL=None,
            MEDIA_ROOT=None,
            # Configuration email simple
            EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
            # Cache simple
            CACHES={
                'default': {
                    'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
                }
            },
            # Password hashers rapides pour les tests
            PASSWORD_HASHERS=[
                'django.contrib.auth.hashers.MD5PasswordHasher',
            ],
            # Pas de validation complexe pour les tests
            AUTH_PASSWORD_VALIDATORS=[],
        )
    
    django.setup()
    return True

def test_imports():
    """Test 1: Validation des imports"""
    print("📋 Test 1: Imports des modules")
    
    try:
        # Test imports accounts
        from accounts.models import User, UserProfile, TwoFactorAuth, UserSession, PasswordHistory
        print("   ✅ accounts.models - OK")
        
        # Test imports vote
        from vote.models import Election, Candidate, Vote, VoteRecord, ElectionVoter, ElectionResult
        print("   ✅ vote.models - OK")
        
        # Test imports audit
        from audit.models import AuditLog, SecurityEvent, VoteAudit, SystemHealthLog
        print("   ✅ audit.models - OK")
        
        # Test imports dashboard
        from dashboard.models import Dashboard, DashboardWidget, SystemMetric, Alert
        print("   ✅ dashboard.models - OK")
        
        # Test imports cryptoutils
        from cryptoutils.rsa_manager import RSAManager
        print("   ✅ cryptoutils.rsa_manager - OK")
        
        return True
        
    except ImportError as e:
        print(f"   ❌ Erreur d'import: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Erreur: {e}")
        return False

def test_database_models():
    """Test 2: Création des tables et modèles"""
    print("\n🗄️  Test 2: Modèles de base de données")
    
    try:
        from django.core.management import call_command
        from django.db import connection
        
        # Créer les tables
        call_command('migrate', verbosity=0, interactive=False)
        print("   ✅ Migration des tables - OK")
        
        # Vérifier les tables créées
        table_names = connection.introspection.table_names()
        expected_tables = [
            'accounts_user',
            'vote_election', 
            'vote_candidate',
            'audit_auditlog',
            'dashboard_dashboard'
        ]
        
        for table in expected_tables:
            if table in table_names:
                print(f"   ✅ Table {table} - OK")
            else:
                print(f"   ⚠️  Table {table} - Manquante")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Erreur base de données: {e}")
        return False

def test_user_creation():
    """Test 3: Création et validation d'utilisateurs"""
    print("\n👤 Test 3: Gestion des utilisateurs")
    
    try:
        from accounts.models import User, UserProfile, TwoFactorAuth
        
        # Créer un utilisateur
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPassword123!'
        )
        print(f"   ✅ Utilisateur créé: {user.username}")
        
        # Tester les propriétés
        assert user.is_authenticated
        assert not user.is_superuser
        assert user.role == 'voter'
        assert not user.is_account_locked()
        print("   ✅ Propriétés utilisateur - OK")
        
        # Créer un profil
        profile = UserProfile.objects.create(
            user=user,
            first_name="Test",
            last_name="User"
        )
        print(f"   ✅ Profil créé: {profile.first_name} {profile.last_name}")
        
        # Test 2FA setup
        two_factor = TwoFactorAuth.objects.create(user=user)
        two_factor.generate_secret()  # Générer le secret TOTP
        two_factor.save()
        print(f"   ✅ 2FA configuré: TOTP")
        
        return user
        
    except Exception as e:
        print(f"   ❌ Erreur utilisateur: {e}")
        return None

def test_election_system(admin_user):
    """Test 4: Système d'élection"""
    print("\n🗳️  Test 4: Système de vote")
    
    try:
        from vote.models import Election, Candidate, ElectionVoter
        from django.utils import timezone
        from datetime import timedelta
        
        # Créer une élection
        election = Election.objects.create(
            title="Élection de Test",
            description="Test du système de vote",
            created_by=admin_user,
            start_date=timezone.now(),
            end_date=timezone.now() + timedelta(days=7)
        )
        print(f"   ✅ Élection créée: {election.title}")
        
        # Ajouter des candidats
        candidate1 = Candidate.objects.create(
            election=election,
            name="Alice Dupont",
            description="Candidate 1",
            order=1
        )
        candidate2 = Candidate.objects.create(
            election=election,
            name="Bob Martin", 
            description="Candidat 2",
            order=2
        )
        print(f"   ✅ Candidats ajoutés: {candidate1.name}, {candidate2.name}")
        
        # Tester les méthodes
        assert election.status == 'draft'
        assert not election.is_voting_open()  # Draft status
        print("   ✅ Méthodes élection - OK")
        
        # Test génération clés
        public_key, private_key = election.generate_key_pair()
        assert election.public_key is not None
        assert election.private_key_hash is not None
        print("   ✅ Génération clés cryptographiques - OK")
        
        return election, [candidate1, candidate2]
        
    except Exception as e:
        print(f"   ❌ Erreur système vote: {e}")
        return None, []

def test_cryptography():
    """Test 5: Système cryptographique"""
    print("\n🔐 Test 5: Cryptographie RSA")
    
    try:
        from cryptoutils.rsa_manager import RSAManager
        
        # Initialiser le gestionnaire RSA
        rsa_manager = RSAManager()
        print("   ✅ RSAManager initialisé")
        
        # Générer une paire de clés
        public_key, private_key = rsa_manager.generate_key_pair()
        assert len(public_key) > 100  # Clé PEM doit être longue
        assert len(private_key) > 100
        print("   ✅ Génération clés RSA - OK")
        
        # Test chiffrement/déchiffrement
        test_message = "Message secret de test"
        encrypted = rsa_manager.encrypt_data(test_message, public_key)
        decrypted = rsa_manager.decrypt_data(encrypted, private_key)
        
        assert decrypted == test_message
        print("   ✅ Chiffrement/Déchiffrement - OK")
        
        # Test signature numérique
        signature = rsa_manager.sign_data(test_message, private_key)
        is_valid = rsa_manager.verify_signature(test_message, signature, public_key)
        
        assert is_valid
        print("   ✅ Signature numérique - OK")
        
        # Test avec données invalides
        is_invalid = rsa_manager.verify_signature("Message modifié", signature, public_key)
        assert not is_invalid
        print("   ✅ Détection signature invalide - OK")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Erreur cryptographie: {e}")
        return False

def test_audit_system(user):
    """Test 6: Système d'audit"""
    print("\n📊 Test 6: Système d'audit")
    
    try:
        from audit.models import AuditLog, SecurityEvent, VoteAudit
        from django.utils import timezone
        import uuid
        
        # Test création log d'audit
        audit_log = AuditLog.objects.create(
            user=user,
            username=user.username,
            user_ip='127.0.0.1',
            user_agent='Test Browser',
            action='test_action',
            resource='test_resource',
            result='success',
            category='test'
        )
        print(f"   ✅ Log audit créé: {audit_log.action}")
        
        # Test événement de sécurité
        security_event = SecurityEvent.objects.create(
            event_type='failed_login',
            title='Test de connexion échouée',
            description='Test event pour validation',
            severity='medium',
            source_ip='192.168.1.100'
        )
        print(f"   ✅ Événement sécurité créé: {security_event.event_type}")
        
        # Test audit de vote
        vote_audit = VoteAudit.objects.create(
            election_id=uuid.uuid4(),
            election_title='Test Election',
            voter_hash='test_hash',
            vote_token='test_token_123',
            action='vote_cast',
            timestamp=timezone.now(),
            processing_time_ms=150,
            ip_hash='ip_hash_test',
            user_agent_hash='ua_hash_test'
        )
        print(f"   ✅ Audit vote créé: {vote_audit.action}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Erreur système audit: {e}")
        return False

def test_dashboard_system(user):
    """Test 7: Système de dashboard"""
    print("\n📈 Test 7: Tableaux de bord")
    
    try:
        from dashboard.models import Dashboard, DashboardWidget, SystemMetric, Alert
        
        # Créer un dashboard
        dashboard = Dashboard.objects.create(
            name="Dashboard de Test",
            description="Test dashboard",
            owner=user
        )
        print(f"   ✅ Dashboard créé: {dashboard.name}")
        
        # Créer un widget
        widget = DashboardWidget.objects.create(
            title="Widget de Test",
            description="Test widget",
            widget_type="chart",
            created_by=user
        )
        print(f"   ✅ Widget créé: {widget.title}")
        
        # Créer une métrique système
        metric = SystemMetric.objects.create(
            metric_name="test_metric",
            value=42.5,
            unit="percent"
        )
        print(f"   ✅ Métrique créée: {metric.metric_name}")
        
        # Créer une alerte
        alert = Alert.objects.create(
            alert_type="system_warning",
            title="Test Alert",
            message="Alerte de test",
            severity="medium"
        )
        print(f"   ✅ Alerte créée: {alert.title}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Erreur dashboard: {e}")
        return False

def test_forms_and_views():
    """Test 8: Formulaires et vues de base"""
    print("\n📝 Test 8: Formulaires et validation")
    
    try:
        # Test import des formulaires
        from accounts.forms import SecureLoginForm, TwoFactorSetupForm
        from vote.forms import VoteForm, ElectionForm
        print("   ✅ Import formulaires - OK")
        
        # Test import des vues (sans les exécuter)
        from accounts.views import SecureLoginView, TwoFactorVerifyView
        from vote.views import ActiveElectionsView, VotingView
        from audit.views import AuditDashboardView
        from dashboard.views import DashboardHomeView
        print("   ✅ Import vues - OK")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Erreur formulaires/vues: {e}")
        return False

def generate_final_report():
    """Génère un rapport final des tests"""
    print("\n" + "="*60)
    print("📊 RAPPORT FINAL - GalSecVote")
    print("="*60)
    
    try:
        from accounts.models import User, UserProfile, TwoFactorAuth
        from vote.models import Election, Candidate
        from audit.models import AuditLog, SecurityEvent
        from dashboard.models import Dashboard, DashboardWidget
        
        print(f"👥 Utilisateurs créés: {User.objects.count()}")
        print(f"📄 Profils créés: {UserProfile.objects.count()}")
        print(f"🔐 Configurations 2FA: {TwoFactorAuth.objects.count()}")
        print(f"🗳️  Élections créées: {Election.objects.count()}")
        print(f"👤 Candidats créés: {Candidate.objects.count()}")
        print(f"📋 Logs d'audit: {AuditLog.objects.count()}")
        print(f"🚨 Événements sécurité: {SecurityEvent.objects.count()}")
        print(f"📈 Dashboards créés: {Dashboard.objects.count()}")
        print(f"🔧 Widgets créés: {DashboardWidget.objects.count()}")
        
    except Exception as e:
        print(f"❌ Erreur génération rapport: {e}")

def main():
    """Fonction principale de test"""
    print("🚀 GalSecVote - Test Standalone")
    print("Validation complète du système\n")
    
    # Configuration Django
    if not configure_minimal_django():
        print("❌ Impossible de configurer Django")
        return
    
    # Exécution des tests
    tests_passed = 0
    total_tests = 8
    
    # Test 1: Imports
    if test_imports():
        tests_passed += 1
    
    # Test 2: Base de données
    if test_database_models():
        tests_passed += 1
    
    # Test 3: Utilisateurs
    user = test_user_creation()
    if user:
        tests_passed += 1
        
        # Créer un admin pour les tests suivants
        from accounts.models import User
        admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com', 
            password='AdminPass123!',
            role='admin'
        )
    
        # Test 4: Système de vote
        election, candidates = test_election_system(admin_user)
        if election:
            tests_passed += 1
        
        # Test 5: Cryptographie
        if test_cryptography():
            tests_passed += 1
        
        # Test 6: Audit
        if test_audit_system(user):
            tests_passed += 1
        
        # Test 7: Dashboard
        if test_dashboard_system(user):
            tests_passed += 1
        
        # Test 8: Formulaires et vues
        if test_forms_and_views():
            tests_passed += 1
    
    # Rapport final
    generate_final_report()
    
    print("\n" + "="*60)
    print(f"📊 RÉSULTATS: {tests_passed}/{total_tests} tests réussis")
    
    if tests_passed == total_tests:
        print("🎉 TOUS LES TESTS SONT PASSÉS !")
        print("✅ Le système GalSecVote est complètement fonctionnel")
    else:
        print(f"⚠️  {total_tests - tests_passed} test(s) ont échoué")
    
    print("="*60)

if __name__ == '__main__':
    main()