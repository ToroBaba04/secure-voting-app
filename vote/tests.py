# vote/tests.py - Tests pour le système de vote cryptographique de GalSecVote
"""
Tests unitaires et d'intégration pour le système de vote sécurisé
Exigence: Tests complets des fonctionnalités cryptographiques et de vote
"""

import json
import hashlib
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from unittest.mock import patch, MagicMock
from datetime import timedelta

from .models import Election, Candidate, Vote, VoteRecord, ElectionVoter, ElectionResult
from .encryption import VoteEncryption, VoteBatch, VoteDecryption
from .vote_processor import VoteProcessor, VoteValidator, VoteCounter
from .forms import VoteForm, ElectionForm, CandidateForm
from accounts.models import TwoFactorAuth
from cryptoutils.models import KeyPair, CryptographicOperation

User = get_user_model()


class VoteEncryptionTest(TestCase):
    """Tests pour le système de chiffrement des votes"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testvoter',
            email='voter@esp.sn',
            password='TestPassword123!'
        )
        
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
        
        # Créer une élection
        self.election = Election.objects.create(
            title="Test Election",
            description="Election de test",
            created_by=self.admin,
            start_date=timezone.now() - timedelta(hours=1),
            end_date=timezone.now() + timedelta(hours=1),
            status='active',
            is_active=True
        )
        
        # Générer les clés pour l'élection
        self.election.generate_key_pair()
        
        # Créer des candidats
        self.candidate1 = Candidate.objects.create(
            election=self.election,
            name="Candidat 1",
            order=1
        )
        
        self.candidate2 = Candidate.objects.create(
            election=self.election,
            name="Candidat 2",
            order=2
        )
        
        # Ajouter l'utilisateur comme électeur
        ElectionVoter.objects.create(
            election=self.election,
            user=self.user,
            added_by=self.admin,
            is_eligible=True
        )
    
    def test_vote_encryption_basic(self):
        """Test de base du chiffrement de vote"""
        encryption = VoteEncryption(self.election)
        
        encrypted_result = encryption.encrypt_vote(
            candidate_choice=str(self.candidate1.id),
            voter_id=str(self.user.id)
        )
        
        # Vérifier la structure du résultat
        required_fields = [
            'vote_token', 'encrypted_data', 'digital_signature',
            'choice_hash', 'voter_hash', 'timestamp'
        ]
        
        for field in required_fields:
            self.assertIn(field, encrypted_result)
        
        # Vérifier le format du token
        self.assertEqual(len(encrypted_result['vote_token']), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in encrypted_result['vote_token']))
        
        # Vérifier que les données sont chiffrées
        self.assertNotIn(str(self.candidate1.id), encrypted_result['encrypted_data'])
    
    def test_vote_integrity_verification(self):
        """Test de vérification d'intégrité"""
        encryption = VoteEncryption(self.election)
        
        encrypted_vote = encryption.encrypt_vote(
            candidate_choice=str(self.candidate1.id),
            voter_id=str(self.user.id)
        )
        
        # Le vote doit être valide
        self.assertTrue(encryption.verify_vote_integrity(encrypted_vote))
        
        # Corrompre la signature
        corrupted_vote = encrypted_vote.copy()
        corrupted_vote['digital_signature'] = 'corrupted_signature'
        
        self.assertFalse(encryption.verify_vote_integrity(corrupted_vote))
    
    def test_vote_anonymization(self):
        """Test de l'anonymisation des électeurs"""
        encryption = VoteEncryption(self.election)
        
        # Chiffrer deux votes du même utilisateur
        vote1 = encryption.encrypt_vote(
            candidate_choice=str(self.candidate1.id),
            voter_id=str(self.user.id)
        )
        
        vote2 = encryption.encrypt_vote(
            candidate_choice=str(self.candidate1.id),
            voter_id=str(self.user.id)
        )
        
        # Les hashes des électeurs devraient être différents (salt différent)
        self.assertNotEqual(vote1['voter_hash'], vote2['voter_hash'])
        
        # Mais les hashes de choix devraient être identiques
        self.assertEqual(vote1['choice_hash'], vote2['choice_hash'])
    
    def test_choice_hash_consistency(self):
        """Test de cohérence des hashes de choix"""
        encryption = VoteEncryption(self.election)
        
        # Deux votes pour le même candidat
        vote1 = encryption.encrypt_vote(
            candidate_choice=str(self.candidate1.id),
            voter_id=str(self.user.id)
        )
        
        vote2 = encryption.encrypt_vote(
            candidate_choice=str(self.candidate1.id),
            voter_id="another_voter"
        )
        
        # Les hashes de choix doivent être identiques
        self.assertEqual(vote1['choice_hash'], vote2['choice_hash'])
        
        # Vote pour un candidat différent
        vote3 = encryption.encrypt_vote(
            candidate_choice=str(self.candidate2.id),
            voter_id=str(self.user.id)
        )
        
        # Le hash doit être différent
        self.assertNotEqual(vote1['choice_hash'], vote3['choice_hash'])


class VoteBatchTest(TestCase):
    """Tests pour le traitement en lot des votes"""
    
    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
        
        self.election = Election.objects.create(
            title="Batch Test Election",
            description="Test du traitement en lot",
            created_by=self.admin,
            start_date=timezone.now() - timedelta(hours=1),
            end_date=timezone.now() + timedelta(hours=1),
            status='active',
            is_active=True
        )
        
        self.election.generate_key_pair()
        
        self.candidate = Candidate.objects.create(
            election=self.election,
            name="Test Candidate",
            order=1
        )
    
    def test_batch_processing(self):
        """Test du traitement en lot"""
        batch = VoteBatch(self.election)
        
        # Ajouter plusieurs votes au lot
        for i in range(5):
            batch.add_vote(
                candidate_choice=str(self.candidate.id),
                voter_id=f"voter_{i}"
            )
        
        self.assertEqual(len(batch.votes_batch), 5)
        
        # Traiter le lot
        result = batch.process_batch()
        
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['processed'], 5)
        self.assertEqual(result['errors'], 0)
        self.assertIn('batch_hash', result)
    
    def test_batch_integrity_hash(self):
        """Test du hash d'intégrité du lot"""
        batch = VoteBatch(self.election)
        
        # Ajouter des votes
        batch.add_vote(str(self.candidate.id), "voter_1")
        batch.add_vote(str(self.candidate.id), "voter_2")
        
        # Traiter le lot
        result1 = batch.process_batch()
        hash1 = result1['batch_hash']
        
        # Nouveau lot avec les mêmes votes
        batch2 = VoteBatch(self.election)
        batch2.add_vote(str(self.candidate.id), "voter_1")
        batch2.add_vote(str(self.candidate.id), "voter_2")
        
        result2 = batch2.process_batch()
        hash2 = result2['batch_hash']
        
        # Les hashes devraient être différents (timestamps différents)
        self.assertNotEqual(hash1, hash2)


class VoteProcessorTest(TestCase):
    """Tests pour le processeur de votes"""
    
    def setUp(self):
        self.voter = User.objects.create_user(
            username='voter',
            email='voter@esp.sn',
            password='VoterPassword123!'
        )
        
        # Configurer 2FA pour l'électeur
        two_factor = TwoFactorAuth.objects.create(user=self.voter)
        two_factor.generate_secret()
        two_factor.is_verified = True
        two_factor.save()
        
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
        
        self.election = Election.objects.create(
            title="Processor Test Election",
            description="Test du processeur de votes",
            created_by=self.admin,
            start_date=timezone.now() - timedelta(hours=1),
            end_date=timezone.now() + timedelta(hours=1),
            status='active',
            is_active=True
        )
        
        self.election.generate_key_pair()
        
        self.candidate = Candidate.objects.create(
            election=self.election,
            name="Test Candidate",
            order=1
        )
        
        # Ajouter l'électeur
        ElectionVoter.objects.create(
            election=self.election,
            user=self.voter,
            added_by=self.admin,
            is_eligible=True
        )
    
    def test_successful_vote_processing(self):
        """Test du traitement réussi d'un vote"""
        processor = VoteProcessor(self.election)
        
        result = processor.process_vote(
            voter=self.voter,
            candidate_id=str(self.candidate.id)
        )
        
        self.assertTrue(result['success'])
        self.assertIn('vote_id', result)
        self.assertIn('receipt', result)
        
        # Vérifier que le vote a été enregistré
        self.assertTrue(Vote.objects.filter(election=self.election).exists())
        self.assertTrue(VoteRecord.objects.filter(
            election=self.election,
            voter=self.voter
        ).exists())
    
    def test_double_vote_prevention(self):
        """Test de prévention du double vote"""
        processor = VoteProcessor(self.election)
        
        # Premier vote
        result1 = processor.process_vote(
            voter=self.voter,
            candidate_id=str(self.candidate.id)
        )
        self.assertTrue(result1['success'])
        
        # Tentative de second vote
        result2 = processor.process_vote(
            voter=self.voter,
            candidate_id=str(self.candidate.id)
        )
        self.assertFalse(result2['success'])
        self.assertEqual(result2['error_type'], 'validation')
    
    def test_vote_eligibility_validation(self):
        """Test de validation d'éligibilité"""
        # Utilisateur non éligible
        non_eligible_user = User.objects.create_user(
            username='noneligible',
            email='noneligible@esp.sn',
            password='Password123!'
        )
        
        processor = VoteProcessor(self.election)
        
        result = processor.process_vote(
            voter=non_eligible_user,
            candidate_id=str(self.candidate.id)
        )
        
        self.assertFalse(result['success'])
        self.assertEqual(result['error_type'], 'validation')
    
    def test_invalid_candidate_rejection(self):
        """Test de rejet d'un candidat invalide"""
        processor = VoteProcessor(self.election)
        
        result = processor.process_vote(
            voter=self.voter,
            candidate_id="invalid_candidate_id"
        )
        
        self.assertFalse(result['success'])
        self.assertEqual(result['error_type'], 'validation')
    
    def test_closed_election_rejection(self):
        """Test de rejet pour élection fermée"""
        # Fermer l'élection
        self.election.status = 'closed'
        self.election.is_active = False
        self.election.save()
        
        processor = VoteProcessor(self.election)
        
        result = processor.process_vote(
            voter=self.voter,
            candidate_id=str(self.candidate.id)
        )
        
        self.assertFalse(result['success'])
        self.assertEqual(result['error_type'], 'validation')


class VoteValidatorTest(TestCase):
    """Tests pour le validateur de votes"""
    
    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
        
        self.election = Election.objects.create(
            title="Validator Test Election",
            description="Test du validateur",
            created_by=self.admin,
            start_date=timezone.now() - timedelta(hours=2),
            end_date=timezone.now() - timedelta(hours=1),  # Élection fermée
            status='closed',
            is_active=False
        )
        
        self.election.generate_key_pair()
        
        self.candidate = Candidate.objects.create(
            election=self.election,
            name="Test Candidate",
            order=1
        )
    
    def test_vote_data_validation(self):
        """Test de validation des données de vote"""
        validator = VoteValidator(self.election)
        
        # Vote valide
        valid_vote = {
            'vote_token': 'a' * 64,  # 64 caractères hexadécimaux
            'encrypted_data': 'encrypted_content',
            'digital_signature': 'signature',
            'choice_hash': 'choice_hash',
            'voter_hash': 'voter_hash',
            'timestamp': timezone.now().isoformat()
        }
        
        result = validator.validate_vote_data(valid_vote)
        self.assertTrue(result['valid'])
        self.assertEqual(len(result['errors']), 0)
        
        # Vote invalide (champ manquant)
        invalid_vote = valid_vote.copy()
        del invalid_vote['vote_token']
        
        result = validator.validate_vote_data(invalid_vote)
        self.assertFalse(result['valid'])
        self.assertGreater(len(result['errors']), 0)
    
    def test_election_integrity_validation(self):
        """Test de validation d'intégrité d'élection"""
        validator = VoteValidator(self.election)
        
        # Créer quelques votes de test
        encryption = VoteEncryption(self.election)
        for i in range(3):
            encrypted_vote = encryption.encrypt_vote(
                candidate_choice=str(self.candidate.id),
                voter_id=f"voter_{i}"
            )
            
            Vote.objects.create(
                election=self.election,
                encrypted_choice=encrypted_vote['encrypted_data'],
                choice_hash=encrypted_vote['choice_hash'],
                digital_signature=encrypted_vote['digital_signature'],
                vote_token=encrypted_vote['vote_token'],
                ip_hash=hashlib.sha256(f"192.168.1.{i}".encode()).hexdigest()
            )
        
        # Valider l'intégrité
        report = validator.validate_election_integrity()
        
        self.assertIn('overall_status', report)
        self.assertIn('checks', report)
        self.assertIn('cryptographic_keys', report['checks'])
        self.assertIn('votes_integrity', report['checks'])
    
    def test_token_format_validation(self):
        """Test de validation du format des tokens"""
        validator = VoteValidator(self.election)
        
        # Token valide
        valid_token = 'a' * 64
        self.assertTrue(validator._is_valid_token_format(valid_token))
        
        # Token trop court
        short_token = 'a' * 32
        self.assertFalse(validator._is_valid_token_format(short_token))
        
        # Token avec caractères invalides
        invalid_token = 'g' * 64
        self.assertFalse(validator._is_valid_token_format(invalid_token))


class VoteCounterTest(TestCase):
    """Tests pour le compteur de votes"""
    
    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
        
        self.election = Election.objects.create(
            title="Counter Test Election",
            description="Test du compteur",
            created_by=self.admin,
            start_date=timezone.now() - timedelta(hours=2),
            end_date=timezone.now() - timedelta(hours=1),
            status='closed',
            is_active=False
        )
        
        self.election.generate_key_pair()
        
        # Créer des candidats
        self.candidate1 = Candidate.objects.create(
            election=self.election,
            name="Candidat 1",
            order=1
        )
        
        self.candidate2 = Candidate.objects.create(
            election=self.election,
            name="Candidat 2",
            order=2
        )
        
        # Créer des électeurs éligibles
        for i in range(10):
            user = User.objects.create_user(
                username=f'voter_{i}',
                email=f'voter_{i}@esp.sn',
                password='Password123!'
            )
            ElectionVoter.objects.create(
                election=self.election,
                user=user,
                added_by=self.admin,
                is_eligible=True
            )
    
    def test_vote_counting(self):
        """Test du comptage des votes"""
        # Créer des votes de test
        encryption = VoteEncryption(self.election)
        
        # 6 votes pour le candidat 1
        candidate1_hash = self.candidate1.get_choice_hash()
        for i in range(6):
            encrypted_vote = encryption.encrypt_vote(
                candidate_choice=str(self.candidate1.id),
                voter_id=f"voter_{i}"
            )
            
            Vote.objects.create(
                election=self.election,
                encrypted_choice=encrypted_vote['encrypted_data'],
                choice_hash=candidate1_hash,
                digital_signature=encrypted_vote['digital_signature'],
                vote_token=encrypted_vote['vote_token'],
                ip_hash=hashlib.sha256(f"192.168.1.{i}".encode()).hexdigest(),
                is_valid=True,
                is_counted=True
            )
        
        # 4 votes pour le candidat 2
        candidate2_hash = self.candidate2.get_choice_hash()
        for i in range(6, 10):
            encrypted_vote = encryption.encrypt_vote(
                candidate_choice=str(self.candidate2.id),
                voter_id=f"voter_{i}"
            )
            
            Vote.objects.create(
                election=self.election,
                encrypted_choice=encrypted_vote['encrypted_data'],
                choice_hash=candidate2_hash,
                digital_signature=encrypted_vote['digital_signature'],
                vote_token=encrypted_vote['vote_token'],
                ip_hash=hashlib.sha256(f"192.168.1.{i}".encode()).hexdigest(),
                is_valid=True,
                is_counted=True
            )
        
        # Compter les votes
        counter = VoteCounter(self.election)
        results = counter.count_votes()
        
        # Vérifier les résultats
        self.assertEqual(results['statistics']['total_valid_votes'], 10)
        self.assertEqual(results['statistics']['eligible_voters'], 10)
        self.assertEqual(results['statistics']['turnout_percentage'], 100.0)
        
        # Vérifier les résultats par candidat
        candidate1_result = results['results'][str(self.candidate1.id)]
        candidate2_result = results['results'][str(self.candidate2.id)]
        
        self.assertEqual(candidate1_result['vote_count'], 6)
        self.assertEqual(candidate2_result['vote_count'], 4)
        self.assertEqual(candidate1_result['percentage'], 60.0)
        self.assertEqual(candidate2_result['percentage'], 40.0)
    
    def test_empty_election_counting(self):
        """Test du comptage d'une élection sans votes"""
        counter = VoteCounter(self.election)
        results = counter.count_votes()
        
        self.assertEqual(results['statistics']['total_valid_votes'], 0)
        self.assertEqual(results['statistics']['turnout_percentage'], 0.0)
        
        # Tous les candidats devraient avoir 0 vote
        for candidate_result in results['results'].values():
            self.assertEqual(candidate_result['vote_count'], 0)
            self.assertEqual(candidate_result['percentage'], 0)


class VoteFormsTest(TestCase):
    """Tests pour les formulaires de vote"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='user@esp.sn',
            password='Password123!'
        )
        
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
        
        self.election = Election.objects.create(
            title="Form Test Election",
            description="Test des formulaires",
            created_by=self.admin,
            start_date=timezone.now() - timedelta(hours=1),
            end_date=timezone.now() + timedelta(hours=1),
            status='active',
            is_active=True
        )
        
        self.candidate = Candidate.objects.create(
            election=self.election,
            name="Test Candidate",
            order=1
        )
        
        ElectionVoter.objects.create(
            election=self.election,
            user=self.user,
            added_by=self.admin,
            is_eligible=True
        )
    
    def test_vote_form_valid_submission(self):
        """Test de soumission valide du formulaire de vote"""
        form_data = {
            'candidate': self.candidate.id,
            'confirmation': True
        }
        
        form = VoteForm(
            election=self.election,
            user=self.user,
            data=form_data
        )
        
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['candidate'], self.candidate)
    
    def test_vote_form_missing_confirmation(self):
        """Test avec confirmation manquante"""
        form_data = {
            'candidate': self.candidate.id,
            'confirmation': False
        }
        
        form = VoteForm(
            election=self.election,
            user=self.user,
            data=form_data
        )
        
        self.assertFalse(form.is_valid())
        self.assertIn('confirmation', form.errors)
    
    def test_election_form_valid_data(self):
        """Test du formulaire d'élection avec données valides"""
        form_data = {
            'title': 'Nouvelle élection',
            'description': 'Description de test',
            'start_date': timezone.now() + timedelta(hours=1),
            'end_date': timezone.now() + timedelta(hours=25),
            'require_2fa': True,
            'allow_vote_change': False,
            'max_votes_per_user': 1,
            'is_anonymous': True
        }
        
        form = ElectionForm(data=form_data)
        
        self.assertTrue(form.is_valid())
    
    def test_election_form_invalid_dates(self):
        """Test avec dates invalides"""
        form_data = {
            'title': 'Élection invalide',
            'description': 'Test',
            'start_date': timezone.now() + timedelta(hours=25),
            'end_date': timezone.now() + timedelta(hours=1),  # Fin avant début
            'require_2fa': True,
            'allow_vote_change': False,
            'max_votes_per_user': 1,
            'is_anonymous': True
        }
        
        form = ElectionForm(data=form_data)
        
        self.assertFalse(form.is_valid())
        self.assertIn('La date de fin doit être postérieure', str(form.errors))


class VoteViewsTest(TestCase):
    """Tests d'intégration pour les vues de vote"""
    
    def setUp(self):
        self.client = Client()
        
        self.voter = User.objects.create_user(
            username='voter',
            email='voter@esp.sn',
            password='VoterPassword123!'
        )
        
        # Configurer 2FA
        two_factor = TwoFactorAuth.objects.create(user=self.voter)
        two_factor.generate_secret()
        two_factor.is_verified = True
        two_factor.save()
        
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
        
        self.election = Election.objects.create(
            title="View Test Election",
            description="Test des vues",
            created_by=self.admin,
            start_date=timezone.now() - timedelta(hours=1),
            end_date=timezone.now() + timedelta(hours=1),
            status='active',
            is_active=True
        )
        
        self.election.generate_key_pair()
        
        self.candidate = Candidate.objects.create(
            election=self.election,
            name="Test Candidate",
            order=1
        )
        
        ElectionVoter.objects.create(
            election=self.election,
            user=self.voter,
            added_by=self.admin,
            is_eligible=True
        )
    
    def test_elections_list_view(self):
        """Test de la vue liste des élections"""
        self.client.login(username='voter', password='VoterPassword123!')
        
        response = self.client.get(reverse('vote:elections_list'))
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.election.title)
    
    def test_voting_view_authenticated_user(self):
        """Test de la vue de vote pour utilisateur authentifié"""
        self.client.login(username='voter', password='VoterPassword123!')
        
        response = self.client.get(
            reverse('vote:vote', kwargs={'pk': self.election.pk})
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.candidate.name)
    
    def test_voting_view_unauthenticated_user(self):
        """Test de redirection pour utilisateur non authentifié"""
        response = self.client.get(
            reverse('vote:vote', kwargs={'pk': self.election.pk})
        )
        
        self.assertEqual(response.status_code, 302)  # Redirection vers login
    
    def test_vote_submission(self):
        """Test de soumission de vote"""
        self.client.login(username='voter', password='VoterPassword123!')
        
        # Première soumission (sans confirmation)
        response = self.client.post(
            reverse('vote:vote', kwargs={'pk': self.election.pk}),
            {
                'candidate_id': str(self.candidate.id)
            }
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'confirmation')
        
        # Soumission avec confirmation
        response = self.client.post(
            reverse('vote:vote', kwargs={'pk': self.election.pk}),
            {
                'candidate_id': str(self.candidate.id),
                'confirmed': 'true'
            }
        )
        
        self.assertEqual(response.status_code, 302)  # Redirection vers succès
        
        # Vérifier que le vote a été enregistré
        self.assertTrue(VoteRecord.objects.filter(
            election=self.election,
            voter=self.voter
        ).exists())
    
    def test_double_vote_prevention_in_view(self):
        """Test de prévention du double vote dans les vues"""
        self.client.login(username='voter', password='VoterPassword123!')
        
        # Premier vote
        self.client.post(
            reverse('vote:vote', kwargs={'pk': self.election.pk}),
            {
                'candidate_id': str(self.candidate.id),
                'confirmed': 'true'
            }
        )
        
        # Tentative de second vote
        response = self.client.get(
            reverse('vote:vote', kwargs={'pk': self.election.pk})
        )
        
        # Devrait rediriger vers la confirmation
        self.assertEqual(response.status_code, 302)
    
    def test_vote_status_api(self):
        """Test de l'API de statut de vote"""
        self.client.login(username='voter', password='VoterPassword123!')
        
        response = self.client.get(
            reverse('vote:api_vote_status', kwargs={'election_id': self.election.id})
        )
        
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        self.assertTrue(data['eligible'])
        self.assertFalse(data['has_voted'])
        self.assertTrue(data['election_open'])
    
    def test_election_results_view_closed_election(self):
        """Test de la vue des résultats pour élection fermée"""
        # Fermer l'élection et créer des résultats
        self.election.status = 'closed'
        self.election.save()
        
        result = ElectionResult.objects.create(
            election=self.election,
            calculated_by=self.admin,
            is_published=True,
            total_votes=10,
            eligible_voters=20,
            turnout_percentage=50.0
        )
        
        self.client.login(username='voter', password='VoterPassword123!')
        
        response = self.client.get(
            reverse('vote:election_results', kwargs={'pk': self.election.pk})
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Résultats')


class VoteCryptographyIntegrationTest(TestCase):
    """Tests d'intégration cryptographique complets"""
    
    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin',
            email='admin@esp.sn',
            password='AdminPassword123!',
            role='admin'
        )
        
        self.election = Election.objects.create(
            title="Crypto Integration Test",
            description="Test d'intégration cryptographique",
            created_by=self.admin,
            start_date=timezone.now() - timedelta(hours=1),
            end_date=timezone.now() + timedelta(hours=1),
            status='active',
            is_active=True
        )
        
        # Générer les clés
        public_key, self.private_key = self.election.generate_key_pair()
        
        self.candidate = Candidate.objects.create(
            election=self.election,
            name="Integration Test Candidate",
            order=1
        )
    
    def test_full_vote_cycle(self):
        """Test du cycle complet de vote avec cryptographie"""
        # 1. Chiffrer un vote
        encryption = VoteEncryption(self.election)
        encrypted_vote = encryption.encrypt_vote(
            candidate_choice=str(self.candidate.id),
            voter_id="test_voter"
        )
        
        # 2. Vérifier l'intégrité
        self.assertTrue(encryption.verify_vote_integrity(encrypted_vote))
        
        # 3. Enregistrer en base
        vote_record = Vote.objects.create(
            election=self.election,
            encrypted_choice=encrypted_vote['encrypted_data'],
            choice_hash=encrypted_vote['choice_hash'],
            digital_signature=encrypted_vote['digital_signature'],
            vote_token=encrypted_vote['vote_token'],
            ip_hash=hashlib.sha256("192.168.1.1".encode()).hexdigest()
        )
        
        # 4. Déchiffrer (pour dépouillement)
        decryption = VoteDecryption(self.election, self.private_key)
        decrypted_data = decryption.rsa_manager.decrypt_large_data(
            encrypted_vote['encrypted_data'],
            self.private_key
        )
        
        vote_content = json.loads(decrypted_data)
        
        # 5. Vérifier que le vote déchiffré correspond au candidat
        self.assertEqual(vote_content['candidate_id'], str(self.candidate.id))
        self.assertEqual(vote_content['election_id'], str(self.election.id))
    
    def test_multiple_votes_batch_processing(self):
        """Test du traitement en lot de plusieurs votes"""
        votes_data = []
        
        # Créer plusieurs votes chiffrés
        encryption = VoteEncryption(self.election)
        for i in range(10):
            encrypted_vote = encryption.encrypt_vote(
                candidate_choice=str(self.candidate.id),
                voter_id=f"voter_{i}"
            )
            votes_data.append(encrypted_vote)
            
            # Enregistrer en base
            Vote.objects.create(
                election=self.election,
                encrypted_choice=encrypted_vote['encrypted_data'],
                choice_hash=encrypted_vote['choice_hash'],
                digital_signature=encrypted_vote['digital_signature'],
                vote_token=encrypted_vote['vote_token'],
                ip_hash=hashlib.sha256(f"192.168.1.{i}".encode()).hexdigest()
            )
        
        # Déchiffrer tous les votes
        decryption = VoteDecryption(self.election, self.private_key)
        results = decryption.decrypt_all_votes(votes_data)
        
        # Vérifier les résultats
        self.assertEqual(results['processed'], 10)
        self.assertEqual(results['errors'], 0)
        self.assertEqual(results['results'][str(self.candidate.id)], 10)
    
    @patch('vote.encryption.CryptographicOperation.log_operation')
    def test_cryptographic_operations_logging(self, mock_log):
        """Test de l'enregistrement des opérations cryptographiques"""
        encryption = VoteEncryption(self.election)
        
        # Chiffrer un vote
        encryption.encrypt_vote(
            candidate_choice=str(self.candidate.id),
            voter_id="test_voter"
        )
        
        # Vérifier que l'opération a été loggée
        mock_log.assert_called()
        
        # Vérifier les paramètres de l'appel
        call_args = mock_log.call_args[1]
        self.assertEqual(call_args['operation_type'], 'encrypt')
        self.assertTrue(call_args['success'])


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
                'vote',
                'audit',
                'cryptoutils',
            ],
            SECRET_KEY='test-secret-key',
            USE_TZ=True,
        )
    
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    failures = test_runner.run_tests(['vote'])
    
    if failures:
        raise SystemExit(1)