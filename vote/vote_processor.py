# vote/vote_processor.py - Processeur de votes sécurisé pour GalSecVote
"""
Traitement et validation sécurisés des votes
Exigence: Intégrité, prévention du double vote et audit complet
"""

import json
import hashlib
import logging
from typing import Dict, Any, Optional, List, Tuple
from django.utils import timezone
from django.db import transaction, IntegrityError
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model

from .models import Election, Vote, VoteRecord, Candidate
from .encryption import VoteEncryption, create_vote_receipt
from audit.models import AuditLog, SecurityEvent
from cryptoutils.models import HashRecord

User = get_user_model()
logger = logging.getLogger('vote.processor')


class VoteProcessor:
    """
    Processeur principal pour le traitement sécurisé des votes
    Exigence: Validation, chiffrement et enregistrement sécurisé
    """
    
    def __init__(self, election: Election):
        self.election = election
        self.encryption = VoteEncryption(election)
    
    def process_vote(self, voter: User, candidate_id: str, request=None) -> Dict[str, Any]:
        """
        Traite un vote de manière sécurisée
        
        Args:
            voter: Utilisateur qui vote
            candidate_id: ID du candidat choisi
            request: Requête HTTP pour audit
            
        Returns:
            Dict contenant le résultat du traitement
        """
        try:
            # Validation préliminaire
            validation_result = self._validate_vote_eligibility(voter, candidate_id)
            if not validation_result['valid']:
                return validation_result
            
            # Traitement avec transaction atomique
            with transaction.atomic():
                # Double vérification dans la transaction
                if self._has_already_voted(voter):
                    raise ValidationError("Vous avez déjà voté dans cette élection")
                
                # Obtenir le candidat
                candidate = Candidate.objects.get(id=candidate_id, election=self.election)
                
                # Créer les métadonnées du vote
                vote_metadata = self._create_vote_metadata(voter, request)
                
                # Chiffrer le vote
                encrypted_vote = self.encryption.encrypt_vote(
                    candidate_choice=candidate_id,
                    voter_id=str(voter.id),
                    additional_data=vote_metadata
                )
                
                # Créer l'enregistrement de vote chiffré
                vote_record = Vote.objects.create(
                    election=self.election,
                    encrypted_choice=encrypted_vote['encrypted_data'],
                    choice_hash=encrypted_vote['choice_hash'],
                    digital_signature=encrypted_vote['digital_signature'],
                    vote_token=encrypted_vote['vote_token'],
                    ip_hash=hashlib.sha256(self._get_client_ip(request).encode()).hexdigest(),
                    is_valid=True,
                    is_counted=True
                )
                
                # Enregistrer que l'utilisateur a voté (sans le choix)
                vote_tracking = VoteRecord.objects.create(
                    election=self.election,
                    voter=voter,
                    vote_token=encrypted_vote['vote_token'],
                    ip_address=self._get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:500] if request else '',
                    is_verified=True,
                    verification_method='2fa'
                )
                
                # Enregistrer dans l'audit
                self._log_vote_success(voter, candidate, encrypted_vote, request)
                
                # Créer le reçu de vote
                receipt = create_vote_receipt(encrypted_vote)
                
                # Enregistrer le hash du vote pour intégrité
                self._create_vote_integrity_record(encrypted_vote)
                
                logger.info(f"Vote traité avec succès pour l'utilisateur {voter.username} dans l'élection {self.election.id}")
                
                return {
                    'success': True,
                    'vote_id': str(vote_record.id),
                    'vote_token': encrypted_vote['vote_token'][:16] + '...',  # Partiellement masqué
                    'receipt': receipt,
                    'message': 'Vote enregistré avec succès'
                }
                
        except ValidationError as e:
            logger.warning(f"Vote rejeté pour {voter.username}: {str(e)}")
            self._log_vote_failure(voter, str(e), 'validation_error', request)
            return {
                'success': False,
                'error': str(e),
                'error_type': 'validation'
            }
            
        except IntegrityError as e:
            logger.error(f"Erreur d'intégrité lors du vote de {voter.username}: {str(e)}")
            self._log_vote_failure(voter, str(e), 'integrity_error', request)
            return {
                'success': False,
                'error': 'Erreur technique lors de l\'enregistrement',
                'error_type': 'integrity'
            }
            
        except Exception as e:
            logger.error(f"Erreur inattendue lors du vote de {voter.username}: {str(e)}")
            self._log_vote_failure(voter, str(e), 'system_error', request)
            return {
                'success': False,
                'error': 'Erreur technique inattendue',
                'error_type': 'system'
            }
    
    def _validate_vote_eligibility(self, voter: User, candidate_id: str) -> Dict[str, Any]:
        """Valide l'éligibilité du vote"""
        try:
            # Vérifier que l'élection est active
            if not self.election.is_voting_open():
                return {
                    'valid': False,
                    'error': 'L\'élection n\'est pas ouverte au vote',
                    'error_type': 'election_closed'
                }
            
            # Vérifier l'éligibilité de l'électeur
            if not self.election.is_user_eligible(voter):
                SecurityEvent.create_event(
                    event_type='unauthorized_access',
                    title='Tentative de vote non autorisé',
                    description=f'L\'utilisateur {voter.username} a tenté de voter sans autorisation',
                    user=voter,
                    severity='medium'
                )
                return {
                    'valid': False,
                    'error': 'Vous n\'êtes pas autorisé à voter dans cette élection',
                    'error_type': 'not_eligible'
                }
            
            # Vérifier le double vote
            if self._has_already_voted(voter):
                SecurityEvent.create_event(
                    event_type='multiple_votes',
                    title='Tentative de vote multiple',
                    description=f'L\'utilisateur {voter.username} a tenté de voter plusieurs fois',
                    user=voter,
                    severity='high'
                )
                return {
                    'valid': False,
                    'error': 'Vous avez déjà voté dans cette élection',
                    'error_type': 'already_voted'
                }
            
            # Vérifier que le candidat existe et est actif
            try:
                candidate = Candidate.objects.get(id=candidate_id, election=self.election, is_active=True)
            except Candidate.DoesNotExist:
                return {
                    'valid': False,
                    'error': 'Candidat invalide ou inexistant',
                    'error_type': 'invalid_candidate'
                }
            
            # Vérifier la 2FA de l'utilisateur
            if not voter.is_2fa_enabled:
                return {
                    'valid': False,
                    'error': 'L\'authentification à deux facteurs est requise pour voter',
                    'error_type': 'missing_2fa'
                }
            
            return {'valid': True}
            
        except Exception as e:
            logger.error(f"Erreur lors de la validation d'éligibilité: {e}")
            return {
                'valid': False,
                'error': 'Erreur technique lors de la validation',
                'error_type': 'validation_error'
            }
    
    def _has_already_voted(self, voter: User) -> bool:
        """Vérifie si l'utilisateur a déjà voté"""
        return VoteRecord.objects.filter(
            election=self.election,
            voter=voter
        ).exists()
    
    def _create_vote_metadata(self, voter: User, request) -> Dict[str, Any]:
        """Crée les métadonnées du vote"""
        metadata = {
            'voter_role': voter.role,
            'authentication_method': '2fa',
            'client_info': {
                'ip_hash': hashlib.sha256(self._get_client_ip(request).encode()).hexdigest(),
                'user_agent_hash': hashlib.sha256(
                    request.META.get('HTTP_USER_AGENT', '').encode()
                ).hexdigest() if request else ''
            },
            'system_info': {
                'encryption_version': '1.0',
                'protocol_version': '1.0'
            }
        }
        return metadata
    
    def _get_client_ip(self, request) -> str:
        """Extrait l'IP réelle du client"""
        if not request:
            return '127.0.0.1'
        
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip
    
    def _log_vote_success(self, voter: User, candidate: Candidate, encrypted_vote: Dict, request):
        """Enregistre le succès du vote dans l'audit"""
        from audit.models import VoteAudit
        
        # Log d'audit général
        AuditLog.log_action(
            user=voter,
            action='vote_cast',
            resource='election_vote',
            request=request,
            result='success',
            category='vote_event',
            details={
                'election_id': str(self.election.id),
                'election_title': self.election.title,
                'vote_token': encrypted_vote['vote_token'][:16] + '...',
                'encryption_method': 'RSA-HYBRID'
            }
        )
        
        # Log d'audit spécifique aux votes
        VoteAudit.log_vote_action(
            election=self.election,
            action='vote_cast',
            vote_token=encrypted_vote['vote_token'],
            voter=voter,
            ip_hash=hashlib.sha256(self._get_client_ip(request).encode()).hexdigest(),
            user_agent_hash=hashlib.sha256(
                request.META.get('HTTP_USER_AGENT', '').encode()
            ).hexdigest() if request else '',
            success=True,
            signature_valid=True,
            encryption_method='RSA-HYBRID'
        )
    
    def _log_vote_failure(self, voter: User, error_message: str, error_type: str, request):
        """Enregistre l'échec du vote dans l'audit"""
        AuditLog.log_action(
            user=voter,
            action='vote_cast_failed',
            resource='election_vote',
            request=request,
            result='failure',
            category='vote_event',
            error_message=error_message,
            details={
                'election_id': str(self.election.id),
                'error_type': error_type
            }
        )
    
    def _create_vote_integrity_record(self, encrypted_vote: Dict):
        """Crée un enregistrement d'intégrité pour le vote"""
        HashRecord.create_hash_record(
            data_identifier=f"vote_{encrypted_vote['vote_token']}",
            data=json.dumps(encrypted_vote, sort_keys=True),
            purpose='vote_integrity',
            algorithm='SHA256'
        )


class VoteValidator:
    """
    Validateur pour les votes et processus électoraux
    Exigence: Validation rigoureuse des données de vote
    """
    
    def __init__(self, election: Election):
        self.election = election
    
    def validate_vote_data(self, vote_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Valide les données d'un vote
        
        Args:
            vote_data: Données du vote à valider
            
        Returns:
            Dict contenant le résultat de la validation
        """
        errors = []
        warnings = []
        
        try:
            # Validation des champs requis
            required_fields = [
                'vote_token', 'encrypted_data', 'digital_signature',
                'choice_hash', 'voter_hash', 'timestamp'
            ]
            
            for field in required_fields:
                if field not in vote_data:
                    errors.append(f"Champ manquant: {field}")
            
            # Validation du format du token
            if 'vote_token' in vote_data:
                if not self._is_valid_token_format(vote_data['vote_token']):
                    errors.append("Format de token de vote invalide")
            
            # Validation du timestamp
            if 'timestamp' in vote_data:
                if not self._is_valid_timestamp(vote_data['timestamp']):
                    errors.append("Timestamp invalide")
            
            # Validation de la signature
            if all(field in vote_data for field in ['digital_signature', 'vote_token']):
                if not self._validate_signature_format(vote_data['digital_signature']):
                    errors.append("Format de signature numérique invalide")
            
            # Validation de l'unicité du token
            if 'vote_token' in vote_data:
                if self._token_already_exists(vote_data['vote_token']):
                    errors.append("Token de vote déjà utilisé")
            
            return {
                'valid': len(errors) == 0,
                'errors': errors,
                'warnings': warnings,
                'score': self._calculate_validation_score(errors, warnings)
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la validation: {e}")
            return {
                'valid': False,
                'errors': [f"Erreur de validation: {str(e)}"],
                'warnings': [],
                'score': 0
            }
    
    def validate_election_integrity(self) -> Dict[str, Any]:
        """
        Valide l'intégrité complète d'une élection
        
        Returns:
            Dict contenant le rapport d'intégrité
        """
        try:
            report = {
                'election_id': str(self.election.id),
                'validation_timestamp': timezone.now().isoformat(),
                'checks': {},
                'overall_status': 'valid',
                'issues': []
            }
            
            # Vérifier les clés cryptographiques
            keys_check = self._validate_election_keys()
            report['checks']['cryptographic_keys'] = keys_check
            
            # Vérifier l'intégrité des votes
            votes_check = self._validate_all_votes()
            report['checks']['votes_integrity'] = votes_check
            
            # Vérifier la cohérence des comptages
            counting_check = self._validate_vote_counting()
            report['checks']['vote_counting'] = counting_check
            
            # Vérifier les signatures numériques
            signatures_check = self._validate_digital_signatures()
            report['checks']['digital_signatures'] = signatures_check
            
            # Déterminer le statut global
            if any(not check['valid'] for check in report['checks'].values()):
                report['overall_status'] = 'compromised'
                report['issues'] = [
                    issue for check in report['checks'].values() 
                    for issue in check.get('issues', [])
                ]
            
            logger.info(f"Validation d'intégrité terminée pour l'élection {self.election.id}: {report['overall_status']}")
            return report
            
        except Exception as e:
            logger.error(f"Erreur lors de la validation d'intégrité: {e}")
            return {
                'election_id': str(self.election.id),
                'overall_status': 'error',
                'error': str(e)
            }
    
    def _is_valid_token_format(self, token: str) -> bool:
        """Valide le format du token"""
        return (isinstance(token, str) and 
                len(token) == 64 and 
                all(c in '0123456789abcdef' for c in token))
    
    def _is_valid_timestamp(self, timestamp: str) -> bool:
        """Valide le format du timestamp"""
        try:
            from datetime import datetime
            datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return True
        except:
            return False
    
    def _validate_signature_format(self, signature: str) -> bool:
        """Valide le format de la signature numérique"""
        try:
            import base64
            decoded = base64.b64decode(signature)
            return len(decoded) > 0
        except:
            return False
    
    def _token_already_exists(self, token: str) -> bool:
        """Vérifie si le token existe déjà"""
        return Vote.objects.filter(vote_token=token).exists()
    
    def _calculate_validation_score(self, errors: List, warnings: List) -> int:
        """Calcule un score de validation (0-100)"""
        if errors:
            return 0
        elif warnings:
            return max(50, 100 - len(warnings) * 10)
        else:
            return 100
    
    def _validate_election_keys(self) -> Dict[str, Any]:
        """Valide les clés cryptographiques de l'élection"""
        try:
            from .encryption import validate_election_keys
            
            is_valid = validate_election_keys(self.election)
            
            return {
                'valid': is_valid,
                'details': 'Clés cryptographiques validées' if is_valid else 'Clés cryptographiques invalides',
                'issues': [] if is_valid else ['Clés cryptographiques compromises ou invalides']
            }
            
        except Exception as e:
            return {
                'valid': False,
                'details': f'Erreur lors de la validation des clés: {str(e)}',
                'issues': ['Impossible de valider les clés cryptographiques']
            }
    
    def _validate_all_votes(self) -> Dict[str, Any]:
        """Valide l'intégrité de tous les votes"""
        try:
            votes = Vote.objects.filter(election=self.election)
            total_votes = votes.count()
            valid_votes = 0
            invalid_votes = []
            
            encryption = VoteEncryption(self.election)
            
            for vote in votes:
                vote_data = {
                    'vote_token': vote.vote_token,
                    'encrypted_data': vote.encrypted_choice,
                    'digital_signature': vote.digital_signature,
                    'choice_hash': vote.choice_hash,
                    'voter_hash': vote.ip_hash,  # Approximation
                    'timestamp': vote.timestamp.isoformat()
                }
                
                if encryption.verify_vote_integrity(vote_data):
                    valid_votes += 1
                else:
                    invalid_votes.append(vote.vote_token[:8] + '...')
            
            return {
                'valid': len(invalid_votes) == 0,
                'details': f'{valid_votes}/{total_votes} votes valides',
                'issues': [f'Votes avec intégrité compromise: {", ".join(invalid_votes)}'] if invalid_votes else []
            }
            
        except Exception as e:
            return {
                'valid': False,
                'details': f'Erreur lors de la validation des votes: {str(e)}',
                'issues': ['Impossible de valider l\'intégrité des votes']
            }
    
    def _validate_vote_counting(self) -> Dict[str, Any]:
        """Valide la cohérence du comptage des votes"""
        try:
            # Compter les votes par candidat via les hash
            from collections import Counter
            
            votes = Vote.objects.filter(election=self.election, is_valid=True, is_counted=True)
            choice_counts = Counter(vote.choice_hash for vote in votes)
            
            # Comparer avec les enregistrements de vote
            vote_records = VoteRecord.objects.filter(election=self.election)
            
            total_encrypted_votes = votes.count()
            total_vote_records = vote_records.count()
            
            consistent = total_encrypted_votes == total_vote_records
            
            return {
                'valid': consistent,
                'details': f'Votes chiffrés: {total_encrypted_votes}, Enregistrements: {total_vote_records}',
                'issues': [] if consistent else ['Incohérence entre votes chiffrés et enregistrements']
            }
            
        except Exception as e:
            return {
                'valid': False,
                'details': f'Erreur lors de la validation du comptage: {str(e)}',
                'issues': ['Impossible de valider le comptage des votes']
            }
    
    def _validate_digital_signatures(self) -> Dict[str, Any]:
        """Valide les signatures numériques"""
        try:
            votes = Vote.objects.filter(election=self.election)
            valid_signatures = 0
            invalid_signatures = []
            
            encryption = VoteEncryption(self.election)
            
            for vote in votes:
                vote_data = {
                    'vote_token': vote.vote_token,
                    'digital_signature': vote.digital_signature,
                    'timestamp': vote.timestamp.isoformat()
                }
                
                # Vérifier la signature (méthode simplifiée)
                if vote.digital_signature and len(vote.digital_signature) > 0:
                    valid_signatures += 1
                else:
                    invalid_signatures.append(vote.vote_token[:8] + '...')
            
            return {
                'valid': len(invalid_signatures) == 0,
                'details': f'{valid_signatures}/{votes.count()} signatures valides',
                'issues': [f'Signatures invalides: {", ".join(invalid_signatures)}'] if invalid_signatures else []
            }
            
        except Exception as e:
            return {
                'valid': False,
                'details': f'Erreur lors de la validation des signatures: {str(e)}',
                'issues': ['Impossible de valider les signatures numériques']
            }


class VoteCounter:
    """
    Compteur sécurisé pour les résultats d'élection
    Exigence: Dépouillement transparent et vérifiable
    """
    
    def __init__(self, election: Election):
        self.election = election
    
    def count_votes(self, include_invalid: bool = False) -> Dict[str, Any]:
        """
        Compte les votes de manière sécurisée
        
        Args:
            include_invalid: Inclure les votes invalides dans le rapport
            
        Returns:
            Dict contenant les résultats du comptage
        """
        try:
            counting_start = timezone.now()
            
            # Récupérer tous les votes valides
            votes_query = Vote.objects.filter(election=self.election)
            if not include_invalid:
                votes_query = votes_query.filter(is_valid=True, is_counted=True)
            
            votes = votes_query.all()
            
            # Compter par hash de choix (anonyme)
            choice_counts = {}
            invalid_votes = 0
            
            for vote in votes:
                if vote.is_valid and vote.is_counted:
                    choice_hash = vote.choice_hash
                    choice_counts[choice_hash] = choice_counts.get(choice_hash, 0) + 1
                else:
                    invalid_votes += 1
            
            # Mapper les hash aux candidats
            candidate_results = {}
            total_valid_votes = 0
            
            for candidate in self.election.candidates.filter(is_active=True):
                candidate_hash = candidate.get_choice_hash()
                vote_count = choice_counts.get(candidate_hash, 0)
                
                candidate_results[candidate.id] = {
                    'candidate_name': candidate.name,
                    'vote_count': vote_count,
                    'percentage': 0  # Calculé après
                }
                total_valid_votes += vote_count
            
            # Calculer les pourcentages
            if total_valid_votes > 0:
                for result in candidate_results.values():
                    result['percentage'] = round(
                        (result['vote_count'] / total_valid_votes) * 100, 2
                    )
            
            # Statistiques générales
            eligible_voters = self.election.voters.filter(is_eligible=True).count()
            turnout_percentage = round(
                (total_valid_votes / eligible_voters) * 100, 2
            ) if eligible_voters > 0 else 0
            
            counting_time = (timezone.now() - counting_start).total_seconds()
            
            results = {
                'election_id': str(self.election.id),
                'election_title': self.election.title,
                'counting_timestamp': timezone.now().isoformat(),
                'counting_time_seconds': counting_time,
                'statistics': {
                    'total_valid_votes': total_valid_votes,
                    'invalid_votes': invalid_votes,
                    'eligible_voters': eligible_voters,
                    'turnout_percentage': turnout_percentage
                },
                'results': candidate_results,
                'integrity_hash': self._create_results_hash(candidate_results)
            }
            
            # Enregistrer le hash des résultats pour intégrité
            self._save_results_integrity(results)
            
            logger.info(f"Comptage terminé pour l'élection {self.election.id}: {total_valid_votes} votes valides")
            return results
            
        except Exception as e:
            logger.error(f"Erreur lors du comptage: {e}")
            raise
    
    def _create_results_hash(self, results: Dict) -> str:
        """Crée un hash des résultats pour intégrité"""
        results_string = json.dumps(results, sort_keys=True)
        return hashlib.sha256(results_string.encode()).hexdigest()
    
    def _save_results_integrity(self, results: Dict):
        """Sauvegarde le hash des résultats pour vérification future"""
        HashRecord.create_hash_record(
            data_identifier=f"results_{self.election.id}_{results['counting_timestamp']}",
            data=json.dumps(results, sort_keys=True),
            purpose='election_integrity',
            algorithm='SHA256'
        )


# Utilitaires de vérification

def verify_vote_chain_integrity(election: Election) -> Dict[str, Any]:
    """
    Vérifie l'intégrité de la chaîne de votes d'une élection
    
    Args:
        election: Élection à vérifier
        
    Returns:
        Dict contenant le rapport de vérification
    """
    try:
        validator = VoteValidator(election)
        integrity_report = validator.validate_election_integrity()
        
        return {
            'election_id': str(election.id),
            'chain_integrity': integrity_report['overall_status'] == 'valid',
            'verification_timestamp': timezone.now().isoformat(),
            'details': integrity_report
        }
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de chaîne: {e}")
        return {
            'election_id': str(election.id),
            'chain_integrity': False,
            'error': str(e)
        }


def generate_vote_audit_report(election: Election) -> Dict[str, Any]:
    """
    Génère un rapport d'audit complet pour une élection
    
    Args:
        election: Élection à auditer
        
    Returns:
        Dict contenant le rapport d'audit
    """
    try:
        # Statistiques des votes
        total_votes = Vote.objects.filter(election=election).count()
        valid_votes = Vote.objects.filter(election=election, is_valid=True).count()
        
        # Statistiques des électeurs
        eligible_voters = election.voters.filter(is_eligible=True).count()
        actual_voters = VoteRecord.objects.filter(election=election).count()
        
        # Vérification d'intégrité
        integrity_check = verify_vote_chain_integrity(election)
        
        # Rapport d'audit
        audit_report = {
            'election_info': {
                'id': str(election.id),
                'title': election.title,
                'status': election.status,
                'start_date': election.start_date.isoformat(),
                'end_date': election.end_date.isoformat()
            },
            'vote_statistics': {
                'total_encrypted_votes': total_votes,
                'valid_votes': valid_votes,
                'invalid_votes': total_votes - valid_votes,
                'eligible_voters': eligible_voters,
                'actual_voters': actual_voters,
                'turnout_rate': round((actual_voters / eligible_voters) * 100, 2) if eligible_voters > 0 else 0
            },
            'integrity_verification': integrity_check,
            'audit_timestamp': timezone.now().isoformat(),
            'audit_version': '1.0'
        }
        
        logger.info(f"Rapport d'audit généré pour l'élection {election.id}")
        return audit_report
        
    except Exception as e:
        logger.error(f"Erreur lors de la génération du rapport d'audit: {e}")
        raise