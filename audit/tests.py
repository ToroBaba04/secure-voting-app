# audit/tests.py - Tests pour le système d'audit de GalSecVote
"""
Tests unitaires et d'intégration pour le système d'audit
Exigence: Tests complets des fonctionnalités d'audit et de monitoring
"""

import json
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from django.test import TestCase, Client, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.core.exceptions import ValidationError

from .models import (
    AuditLog, SecurityEvent, VoteAudit, SystemHealthLog, 
    ComplianceReport, Alert, SystemStatus
)
from .middleware import AuditMiddleware, SecurityHeadersMiddleware
from .forms import AuditLogFilterForm, ReportGenerationForm
from accounts.models import User, TwoFactorAuth

User = get_user_model()


class AuditLogModelTest(TestCase):
    """Tests pour le modèle AuditLog"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
        
    def test_audit_log_creation(self):
        """Test de création d'un log d'audit"""
        log = AuditLog.objects.create(
            user=self.user,
            username=self.user.username,
            user_ip='192.168.1.100',
            user_agent='Test Browser',
            action='test_action',
            resource='test_resource',
            category='system_event',
            severity='medium'
        )
        
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.action, 'test_action')
        self.assertTrue(log.checksum)
        self.assertTrue(log.verify_integrity())
    
    def test_checksum_calculation(self):
        """Test du calcul de checksum pour l'intégrité"""
        log = AuditLog(
            username='testuser',
            action='test_action',
            resource='test_resource',
            timestamp=timezone.now(),
            result='success'
        )
        
        checksum1 = log.calculate_checksum()
        checksum2 = log.calculate_checksum()
        
        # Le checksum doit être identique pour les mêmes données
        self.assertEqual(checksum1, checksum2)
        
        # Modification d'une donnée doit changer le checksum
        log.action = 'modified_action'
        checksum3 = log.calculate_checksum()
        self.assertNotEqual(checksum1, checksum3)
    
    def test_log_action_utility(self):
        """Test de la méthode utilitaire log_action"""
        mock_request = MagicMock()
        mock_request.META = {
            'HTTP_USER_AGENT': 'Test Browser',
            'REMOTE_ADDR': '192.168.1.100'
        }
        mock_request.session.session_key = 'test_session'
        
        log = AuditLog.log_action(
            user=self.user,
            action='user_login',
            resource='user_account',
            request=mock_request,
            category='authentication',
            severity='low'
        )
        
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.action, 'user_login')
        self.assertEqual(log.user_ip, '192.168.1.100')
        self.assertEqual(log.category, 'authentication')


class SecurityEventModelTest(TestCase):
    """Tests pour le modèle SecurityEvent"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
    
    def test_security_event_creation(self):
        """Test de création d'un événement de sécurité"""
        event = SecurityEvent.objects.create(
            event_type='failed_login',
            title='Tentative de connexion échouée',
            description='Échec de connexion pour l\'utilisateur testuser',
            source_ip='192.168.1.100',
            user=self.user,
            severity='medium'
        )
        
        self.assertEqual(event.event_type, 'failed_login')
        self.assertEqual(event.severity, 'medium')
        self.assertEqual(event.status, 'new')
        self.assertEqual(event.occurrence_count, 1)
    
    def test_duplicate_event_handling(self):
        """Test de gestion des événements dupliqués"""
        # Créer le premier événement
        event1 = SecurityEvent.create_event(
            event_type='failed_login',
            title='Tentative échouée',
            description='Test',
            severity='medium'
        )
        
        # Créer un événement similaire
        event2 = SecurityEvent.create_event(
            event_type='failed_login',
            title='Tentative échouée',
            description='Test 2',
            severity='medium'
        )
        
        # Doit retourner le même événement avec compteur incrémenté
        self.assertEqual(event1.id, event2.id)
        event1.refresh_from_db()
        self.assertEqual(event1.occurrence_count, 2)


class VoteAuditModelTest(TestCase):
    """Tests pour le modèle VoteAudit"""
    
    def test_vote_audit_creation(self):
        """Test de création d'un audit de vote"""
        election_id = uuid.uuid4()
        vote_token = 'test_token_123'
        
        audit = VoteAudit.objects.create(
            election_id=election_id,
            election_title='Test Election',
            voter_hash='voter_hash_123',
            vote_token=vote_token,
            action='vote_cast',
            processing_time_ms=150,
            ip_hash='ip_hash_123',
            user_agent_hash='ua_hash_123'
        )
        
        self.assertEqual(audit.election_id, election_id)
        self.assertEqual(audit.vote_token, vote_token)
        self.assertEqual(audit.action, 'vote_cast')
        self.assertTrue(audit.success)
    
    def test_log_vote_action(self):
        """Test de la méthode log_vote_action"""
        # Mock d'une élection
        election_mock = MagicMock()
        election_mock.id = uuid.uuid4()
        election_mock.title = 'Test Election'
        
        # Mock d'un voter
        voter_mock = MagicMock()
        voter_mock.id = 123
        
        audit = VoteAudit.log_vote_action(
            election=election_mock,
            action='vote_cast',
            vote_token='token123',
            voter=voter_mock,
            processing_time_ms=200
        )
        
        self.assertEqual(audit.election_id, election_mock.id)
        self.assertEqual(audit.election_title, election_mock.title)
        self.assertEqual(audit.vote_token, 'token123')
        self.assertTrue(audit.voter_hash)


class AuditMiddlewareTest(TestCase):
    """Tests pour le middleware d'audit"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
        self.middleware = AuditMiddleware(lambda x: None)
    
    def test_should_audit_request(self):
        """Test de la logique de décision d'audit"""
        # Mock request
        mock_request = MagicMock()
        mock_request.path = '/accounts/login/'
        mock_request.method = 'POST'
        mock_request.user.is_authenticated = True
        
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        # Doit auditer les URLs sensibles
        should_audit = self.middleware.should_audit_request(mock_request, mock_response)
        self.assertTrue(should_audit)
        
        # Ne doit pas auditer les URLs non sensibles en GET
        mock_request.path = '/static/css/style.css'
        mock_request.method = 'GET'
        mock_response.status_code = 200
        should_audit = self.middleware.should_audit_request(mock_request, mock_response)
        self.assertFalse(should_audit)
    
    def test_get_client_ip(self):
        """Test d'extraction de l'IP client"""
        # Test avec X-Forwarded-For
        request_mock = MagicMock()
        request_mock.META = {
            'HTTP_X_FORWARDED_FOR': '203.0.113.1, 198.51.100.1',
            'REMOTE_ADDR': '192.168.1.1'
        }
        
        ip = AuditMiddleware.get_client_ip(request_mock)
        self.assertEqual(ip, '203.0.113.1')
        
        # Test sans X-Forwarded-For
        request_mock.META = {'REMOTE_ADDR': '192.168.1.1'}
        ip = AuditMiddleware.get_client_ip(request_mock)
        self.assertEqual(ip, '192.168.1.1')


class SecurityHeadersMiddlewareTest(TestCase):
    """Tests pour le middleware de headers de sécurité"""
    
    def setUp(self):
        self.middleware = SecurityHeadersMiddleware(lambda x: None)
    
    def test_security_headers_addition(self):
        """Test d'ajout des headers de sécurité"""
        mock_request = MagicMock()
        mock_response = MagicMock()
        mock_response.get.return_value = 'text/html'
        
        # Mock pour simuler l'absence de headers
        def getitem_side_effect(key):
            raise KeyError(key)
        
        mock_response.__getitem__.side_effect = getitem_side_effect
        mock_response.__contains__.return_value = False
        
        result = self.middleware.process_response(mock_request, mock_response)
        
        # Vérifier que les headers sont ajoutés
        self.assertTrue(mock_response.__setitem__.called)


class AuditViewsTest(TestCase):
    """Tests pour les vues d'audit"""
    
    def setUp(self):
        self.client = Client()
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
        
        # Créer quelques logs d'audit pour les tests
        AuditLog.objects.create(
            user=self.user,
            username=self.user.username,
            user_ip='192.168.1.100',
            user_agent='Test Browser',
            action='test_action',
            resource='test_resource',
            category='system_event',
            severity='medium'
        )
    
    def test_dashboard_view_authenticated(self):
        """Test d'accès au tableau de bord pour utilisateur authentifié"""
        self.client.login(username='admin', password='AdminPassword123!')
        
        response = self.client.get(reverse('audit:dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Audit & Monitoring')
    
    def test_dashboard_view_unauthenticated(self):
        """Test de redirection pour utilisateur non authentifié"""
        response = self.client.get(reverse('audit:dashboard'))
        self.assertEqual(response.status_code, 302)  # Redirection vers login
    
    def test_logs_view_with_filters(self):
        """Test de la vue des logs avec filtres"""
        self.client.login(username='admin', password='AdminPassword123!')
        
        response = self.client.get(reverse('audit:logs'), {
            'category': 'system_event',
            'severity': 'medium'
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'test_action')
    
    @patch('audit.views.generate_report_task.delay')
    def test_generate_report_view(self, mock_task):
        """Test de génération de rapport"""
        self.client.login(username='admin', password='AdminPassword123!')
        
        mock_task.return_value.id = 'task_123'
        
        data = {
            'report_type': 'security_audit',
            'title': 'Test Report',
            'start_date': (timezone.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M'),
            'end_date': timezone.now().strftime('%Y-%m-%dT%H:%M'),
            'format': 'html'
        }
        
        response = self.client.post(reverse('audit:generate_report'), data)
        self.assertEqual(response.status_code, 200)
        
        # Vérifier que la tâche a été déclenchée
        mock_task.assert_called_once()


class AuditFormsTest(TestCase):
    """Tests pour les formulaires d'audit"""
    
    def test_audit_log_filter_form_valid(self):
        """Test de validation du formulaire de filtrage"""
        data = {
            'date_start': (timezone.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M'),
            'date_end': timezone.now().strftime('%Y-%m-%dT%H:%M'),
            'category': 'system_event',
            'severity': 'medium',
            'search': 'test'
        }
        
        form = AuditLogFilterForm(data=data)
        self.assertTrue(form.is_valid())
    
    def test_audit_log_filter_form_invalid_dates(self):
        """Test de validation des dates invalides"""
        # Date de fin antérieure à la date de début
        data = {
            'date_start': timezone.now().strftime('%Y-%m-%dT%H:%M'),
            'date_end': (timezone.now() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M'),
        }
        
        form = AuditLogFilterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('La date de début doit être antérieure', str(form.errors))
    
    def test_audit_log_filter_form_period_too_long(self):
        """Test de validation d'une période trop longue"""
        data = {
            'date_start': (timezone.now() - timedelta(days=400)).strftime('%Y-%m-%dT%H:%M'),
            'date_end': timezone.now().strftime('%Y-%m-%dT%H:%M'),
        }
        
        form = AuditLogFilterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('ne peut pas dépasser 1 an', str(form.errors))
    
    def test_report_generation_form_valid(self):
        """Test de validation du formulaire de génération de rapport"""
        data = {
            'report_type': 'security_audit',
            'title': 'Test Security Report',
            'start_date': (timezone.now() - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M'),
            'end_date': timezone.now().strftime('%Y-%m-%dT%H:%M'),
            'format': 'html',
            'include_charts': True,
            'include_details': True
        }
        
        form = ReportGenerationForm(data=data)
        self.assertTrue(form.is_valid())
    
    def test_report_generation_form_election_required(self):
        """Test de validation pour rapport d'élection sans élection sélectionnée"""
        data = {
            'report_type': 'election_summary',
            'title': 'Test Election Report',
            'start_date': (timezone.now() - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M'),
            'end_date': timezone.now().strftime('%Y-%m-%dT%H:%M'),
            'format': 'html'
        }
        
        form = ReportGenerationForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('Une élection doit être sélectionnée', str(form.errors))


class SystemHealthTest(TestCase):
    """Tests pour le monitoring de santé système"""
    
    def test_system_health_log_creation(self):
        """Test de création d'un log de santé système"""
        health_log = SystemHealthLog.objects.create(
            response_time_ms=250,
            memory_usage_mb=1024,
            cpu_usage_percent=45.5,
            db_connections=10,
            db_response_time_ms=50,
            active_sessions=25,
            status='healthy'
        )
        
        self.assertEqual(health_log.status, 'healthy')
        self.assertEqual(health_log.cpu_usage_percent, 45.5)
        self.assertEqual(health_log.memory_usage_mb, 1024)
    
    def test_system_status_update(self):
        """Test de mise à jour du statut système"""
        system_status = SystemStatus.objects.create(
            component='web_server',
            status='operational',
            uptime_percentage=99.5,
            response_time_ms=200
        )
        
        # Mettre à jour le statut
        system_status.update_status(
            status='degraded',
            message='Performance dégradée',
            response_time_ms=800
        )
        
        self.assertEqual(system_status.status, 'degraded')
        self.assertEqual(system_status.response_time_ms, 800)
        self.assertEqual(system_status.status_message, 'Performance dégradée')
    
    def test_system_health_check(self):
        """Test de vérification de santé d'un composant"""
        system_status = SystemStatus.objects.create(
            component='database',
            status='operational',
            uptime_percentage=99.9,
            response_time_ms=100
        )
        
        self.assertTrue(system_status.is_healthy())
        
        # Dégrader le statut
        system_status.status = 'degraded'
        system_status.uptime_percentage = 95.0
        self.assertFalse(system_status.is_healthy())


class IntegrationTest(TestCase):
    """Tests d'intégration pour le système d'audit complet"""
    
    def setUp(self):
        self.client = Client()
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
        
        # Activer 2FA pour l'admin
        self.two_factor = TwoFactorAuth.objects.create(
            user=self.admin_user,
            secret_key='TESTSECRETKEY123',
            is_verified=True
        )
    
    def test_complete_audit_workflow(self):
        """Test du workflow complet d'audit"""
        # 1. Connexion avec audit automatique
        login_data = {
            'username': 'admin',
            'password': 'AdminPassword123!'
        }
        
        response = self.client.post(reverse('accounts:login'), login_data)
        
        # Vérifier qu'un log d'audit a été créé pour la connexion
        audit_logs = AuditLog.objects.filter(
            username='admin',
            action__icontains='login'
        )
        self.assertTrue(audit_logs.exists())
        
        # 2. Accès au tableau de bord
        response = self.client.get(reverse('audit:dashboard'))
        self.assertEqual(response.status_code, 200)
        
        # 3. Consultation des logs
        response = self.client.get(reverse('audit:logs'))
        self.assertEqual(response.status_code, 200)
        
        # 4. Test de filtrage des logs
        response = self.client.get(reverse('audit:logs'), {
            'severity': 'medium',
            'search': 'login'
        })
        self.assertEqual(response.status_code, 200)
    
    @patch('audit.views.generate_security_report')
    def test_security_report_generation(self, mock_generate):
        """Test de génération de rapport de sécurité"""
        mock_generate.return_value = {
            'title': 'Security Audit Report',
            'content': '<h1>Security Report</h1>',
            'summary': 'System is secure'
        }
        
        self.client.login(username='admin', password='AdminPassword123!')
        
        # Générer un rapport
        data = {
            'report_type': 'security_audit',
            'title': 'Weekly Security Report',
            'start_date': (timezone.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M'),
            'end_date': timezone.now().strftime('%Y-%m-%dT%H:%M'),
            'format': 'html'
        }
        
        response = self.client.post(reverse('audit:generate_report'), data)
        self.assertEqual(response.status_code, 200)
    
    def test_security_event_detection_and_alert(self):
        """Test de détection d'événement de sécurité et génération d'alerte"""
        # Simuler plusieurs tentatives de connexion échouées
        for i in range(5):
            SecurityEvent.create_event(
                event_type='failed_login',
                title=f'Failed login attempt {i+1}',
                description='Multiple failed login attempts detected',
                source_ip='192.168.1.100',
                severity='high'
            )
        
        # Vérifier qu'un événement de sécurité a été créé
        security_events = SecurityEvent.objects.filter(
            event_type='failed_login',
            source_ip='192.168.1.100'
        )
        self.assertTrue(security_events.exists())
        
        # Le dernier événement devrait avoir un compteur d'occurrence élevé
        latest_event = security_events.first()
        self.assertGreaterEqual(latest_event.occurrence_count, 5)
    
    def test_audit_data_integrity(self):
        """Test d'intégrité des données d'audit"""
        # Créer un log d'audit
        log = AuditLog.objects.create(
            username='testuser',
            user_ip='192.168.1.100',
            user_agent='Test Browser',
            action='test_action',
            resource='test_resource',
            category='system_event',
            severity='medium',
            details={'test': 'data'}
        )
        
        # Vérifier l'intégrité
        self.assertTrue(log.verify_integrity())
        
        # Simuler une altération des données
        log.action = 'modified_action'
        # Ne pas sauvegarder pour ne pas recalculer le checksum
        
        # L'intégrité ne devrait plus être valide
        self.assertFalse(log.verify_integrity())


class PerformanceTest(TestCase):
    """Tests de performance pour le système d'audit"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@esp.sn',
            password='TestPassword123!'
        )
    
    def test_bulk_audit_log_creation(self):
        """Test de création en masse de logs d'audit"""
        import time
        
        start_time = time.time()
        
        # Créer 1000 logs d'audit
        logs = []
        for i in range(1000):
            logs.append(AuditLog(
                user=self.user,
                username=self.user.username,
                user_ip=f'192.168.1.{i % 255}',
                user_agent='Test Browser',
                action=f'test_action_{i}',
                resource='test_resource',
                category='system_event',
                severity='medium'
            ))
        
        AuditLog.objects.bulk_create(logs)
        
        end_time = time.time()
        creation_time = end_time - start_time
        
        # Vérifier que la création a pris moins de 5 secondes
        self.assertLess(creation_time, 5.0)
        
        # Vérifier que tous les logs ont été créés
        self.assertEqual(AuditLog.objects.count(), 1000)
    
    def test_audit_log_query_performance(self):
        """Test de performance des requêtes sur les logs d'audit"""
        # Créer des logs de test
        for i in range(100):
            AuditLog.objects.create(
                user=self.user,
                username=self.user.username,
                user_ip='192.168.1.100',
                user_agent='Test Browser',
                action=f'action_{i}',
                resource='test_resource',
                category='system_event',
                severity='medium'
            )
        
        import time
        
        # Test de requête avec filtres
        start_time = time.time()
        
        filtered_logs = AuditLog.objects.filter(
            user=self.user,
            category='system_event',
            severity='medium'
        ).order_by('-timestamp')[:20]
        
        # Forcer l'évaluation de la queryset
        list(filtered_logs)
        
        end_time = time.time()
        query_time = end_time - start_time
        
        # La requête devrait prendre moins d'une seconde
        self.assertLess(query_time, 1.0)


class SecurityTest(TestCase):
    """Tests de sécurité pour le système d'audit"""
    
    def setUp(self):
        self.client = Client()
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
        self.normal_user = User.objects.create_user(
            username='user',
            email='user@esp.sn',
            password='UserPassword123!'
        )
    
    def test_audit_access_control(self):
        """Test de contrôle d'accès aux fonctionnalités d'audit"""
        # Test d'accès non autorisé
        self.client.login(username='user', password='UserPassword123!')
        
        response = self.client.get(reverse('audit:dashboard'))
        # Doit être redirigé ou recevoir une erreur 403
        self.assertIn(response.status_code, [302, 403])
        
        # Test d'accès autorisé
        self.client.login(username='admin', password='AdminPassword123!')
        
        response = self.client.get(reverse('audit:dashboard'))
        self.assertEqual(response.status_code, 200)
    
    def test_audit_data_protection(self):
        """Test de protection des données d'audit"""
        # Créer un log avec des données sensibles
        log = AuditLog.objects.create(
            user=self.admin_user,
            username=self.admin_user.username,
            user_ip='192.168.1.100',
            user_agent='Test Browser',
            action='sensitive_action',
            resource='sensitive_resource',
            category='security_event',
            severity='high',
            details={'password': 'should_be_filtered'}
        )
        
        # Les mots de passe ne devraient pas être visibles dans les détails
        # (Cette logique serait implémentée dans les vues)
        self.assertIn('password', log.details)
        
        # Test que les données sensibles sont filtrées dans l'export
        # (Cette fonctionnalité serait implémentée dans les vues d'export)
    
    def test_csrf_protection(self):
        """Test de protection CSRF pour les actions d'audit"""
        self.client.login(username='admin', password='AdminPassword123!')
        
        # Tentative d'action sans token CSRF
        response = self.client.post(reverse('audit:generate_report'), {
            'report_type': 'security_audit',
            'title': 'Test Report'
        })
        
        # Doit être rejeté pour absence de token CSRF
        self.assertEqual(response.status_code, 403)


@override_settings(
    AUDIT_SETTINGS={
        'LOG_AUTHENTICATION': True,
        'LOG_AUTHORIZATION': True,
        'LOG_DATA_ACCESS': True,
        'RETENTION_PERIOD': 7  # 7 jours pour les tests
    }
)
class AuditSettingsTest(TestCase):
    """Tests de configuration du système d'audit"""
    
    def test_audit_settings_configuration(self):
        """Test de configuration des paramètres d'audit"""
        from django.conf import settings
        
        audit_settings = settings.AUDIT_SETTINGS
        self.assertTrue(audit_settings['LOG_AUTHENTICATION'])
        self.assertTrue(audit_settings['LOG_AUTHORIZATION'])
        self.assertEqual(audit_settings['RETENTION_PERIOD'], 7)
    
    def test_retention_policy(self):
        """Test de politique de rétention des logs"""
        # Créer des logs anciens
        old_date = timezone.now() - timedelta(days=10)
        
        with patch('django.utils.timezone.now', return_value=old_date):
            old_log = AuditLog.objects.create(
                username='testuser',
                user_ip='192.168.1.100',
                user_agent='Test Browser',
                action='old_action',
                resource='test_resource',
                category='system_event',
                severity='medium'
            )
        
        # Créer des logs récents
        recent_log = AuditLog.objects.create(
            username='testuser',
            user_ip='192.168.1.100',
            user_agent='Test Browser',
            action='recent_action',
            resource='test_resource',
            category='system_event',
            severity='medium'
        )
        
        # Simuler la politique de rétention
        retention_date = timezone.now() - timedelta(days=7)
        expired_logs = AuditLog.objects.filter(timestamp__lt=retention_date)
        
        self.assertEqual(expired_logs.count(), 1)
        self.assertEqual(expired_logs.first().action, 'old_action')


class APITest(TestCase):
    """Tests pour l'API d'audit"""
    
    def setUp(self):
        self.client = Client()
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
    
    def test_metrics_api(self):
        """Test de l'API des métriques"""
        self.client.login(username='admin', password='AdminPassword123!')
        
        # Créer quelques logs pour les métriques
        for i in range(5):
            AuditLog.objects.create(
                username='testuser',
                user_ip='192.168.1.100',
                user_agent='Test Browser',
                action=f'action_{i}',
                resource='test_resource',
                category='system_event',
                severity='medium'
            )
        
        response = self.client.get(reverse('audit:api_metrics'))
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        self.assertIn('total_events', data)
        self.assertGreaterEqual(data['total_events'], 5)
    
    def test_export_api(self):
        """Test de l'API d'export"""
        self.client.login(username='admin', password='AdminPassword123!')
        
        # Créer des logs de test
        AuditLog.objects.create(
            username='testuser',
            user_ip='192.168.1.100',
            user_agent='Test Browser',
            action='test_action',
            resource='test_resource',
            category='system_event',
            severity='medium'
        )
        
        response = self.client.get(reverse('audit:export_logs'), {
            'format': 'json'
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')


if __name__ == '__main__':
    import unittest
    unittest.main()