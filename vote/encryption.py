# vote/encryption.py - Gestionnaire de chiffrement des votes pour GalSecVote
"""
Système de chiffrement sécurisé pour les bulletins de vote
Intégration du RSAManager avec le processus de vote
Exigence: Confidentialité et intégrité des votes
"""

import json
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
from django.utils import timezone
from django.conf import settings
from cryptoutils.rsa_manager import RSAManager
from cryptoutils.models import KeyPair, CryptographicOperation, DigitalSignature, HashRecord

logger = logging.getLogger('vote.encryption')


class VoteEncryption:
    """
    Gestionnaire principal pour le chiffrement des votes
    Exigence: Chiffrement bout-en-bout des bulletins de vote
    """
    
    def __init__(self, election):
        self.election = election
        self.rsa_manager = RSAManager()
    
    def encrypt_vote(self, candidate_choice: str, voter_id: str, additional_data: Dict = None) -> Dict[str, Any]:
        """
        Chiffre un vote de manière sécurisée
        
        Args:
            candidate_choice: ID du candidat choisi
            voter_id: ID de l'électeur (pour audit, pas stocké avec le vote)
            additional_data: Données additionnelles optionnelles
            
        Returns:
            Dict contenant le vote chiffré et les métadonnées
        """
        try:
            start_time = timezone.now()
            
            # Préparer les données du vote
            vote_data = {
                'candidate_id': candidate_choice,
                'election_id': str(self.election.id),
                'timestamp': timezone.now().isoformat(),
                'vote_id': secrets.token_hex(16)
            }
            
            if additional_data:
                vote_data.update(additional_data)
            
            # Sérialiser les données
            vote_json = json.dumps(vote_data, sort_keys=True)
            
            # Générer un token unique pour ce vote
            vote_token = self._generate_vote_token(vote_data)
            
            # Chiffrer le vote avec la clé publique de l'élection
            encrypted_vote = self.rsa_manager.encrypt_large_data(
                vote_json, 
                self.election.public_key
            )
            
            # Créer la signature numérique
            vote_signature = self._create_vote_signature(vote_data, vote_token)
            
            # Anonymiser l'électeur (hash irréversible)
            voter_hash = self._anonymize_voter(voter_id, vote_token)
            
            # Créer le hash du choix pour comptage anonyme
            choice_hash = self._create_choice_hash(candidate_choice, str(self.election.id))
            
            # Préparer le résultat
            encrypted_result = {
                'vote_token': vote_token,
                'encrypted_data': encrypted_vote,
                'digital_signature': vote_signature,
                'choice_hash': choice_hash,
                'voter_hash': voter_hash,
                'timestamp': vote_data['timestamp'],
                'encryption_method': 'RSA-HYBRID',
                'validation_hash': self._create_validation_hash(vote_data)
            }
            
            # Enregistrer l'opération cryptographique
            processing_time = int((timezone.now() - start_time).total_seconds() * 1000)
            self._log_crypto_operation(
                'encrypt',
                len(vote_json),
                processing_time,
                voter_id,
                success=True
            )
            
            logger.info(f"Vote chiffré avec succès pour l'élection {self.election.id}")
            return encrypted_result
            
        except Exception as e:
            logger.error(f"Erreur lors du chiffrement du vote: {e}")
            self._log_crypto_operation(
                'encrypt',
                0,
                0,
                voter_id,
                success=False,
                error_message=str(e)
            )
            raise
    
    def decrypt_vote(self, encrypted_vote_data: Dict[str, Any], private_key: str) -> Dict[str, Any]:
        """
        Déchiffre un vote (réservé aux administrateurs autorisés)
        
        Args:
            encrypted_vote_data: Données du vote chiffré
            private_key: Clé privée de déchiffrement
            
        Returns:
            Dict contenant les données du vote déchiffré
        """
        try:
            start_time = timezone.now()
            
            # Vérifier la signature numérique
            if not self._verify_vote_signature(encrypted_vote_data):
                raise ValueError("Signature numérique invalide")
            
            # Déchiffrer les données
            decrypted_json = self.rsa_manager.decrypt_large_data(
                encrypted_vote_data['encrypted_data'],
                private_key
            )
            
            # Parser les données JSON
            vote_data = json.loads(decrypted_json)
            
            # Vérifier l'intégrité
            if not self._verify_vote_integrity(vote_data, encrypted_vote_data):
                raise ValueError("Intégrité du vote compromise")
            
            # Enregistrer l'opération de déchiffrement
            processing_time = int((timezone.now() - start_time).total_seconds() * 1000)
            self._log_crypto_operation(
                'decrypt',
                len(decrypted_json),
                processing_time,
                'system',
                success=True
            )
            
            logger.info(f"Vote déchiffré avec succès: {encrypted_vote_data['vote_token'][:8]}...")
            return vote_data
            
        except Exception as e:
            logger.error(f"Erreur lors du déchiffrement du vote: {e}")
            self._log_crypto_operation(
                'decrypt',
                0,
                0,
                'system',
                success=False,
                error_message=str(e)
            )
            raise
    
    def verify_vote_integrity(self, encrypted_vote_data: Dict[str, Any]) -> bool:
        """
        Vérifie l'intégrité d'un vote chiffré sans le déchiffrer
        
        Args:
            encrypted_vote_data: Données du vote chiffré
            
        Returns:
            bool: True si l'intégrité est vérifiée
        """
        try:
            # Vérifier la signature numérique
            if not self._verify_vote_signature(encrypted_vote_data):
                logger.warning(f"Signature invalide pour le vote {encrypted_vote_data.get('vote_token', 'unknown')}")
                return False
            
            # Vérifier la présence des champs requis
            required_fields = [
                'vote_token', 'encrypted_data', 'digital_signature',
                'choice_hash', 'voter_hash', 'timestamp'
            ]
            
            for field in required_fields:
                if field not in encrypted_vote_data:
                    logger.warning(f"Champ manquant dans le vote: {field}")
                    return False
            
            # Vérifier le format du token
            if not self._is_valid_vote_token(encrypted_vote_data['vote_token']):
                logger.warning(f"Format de token invalide: {encrypted_vote_data['vote_token']}")
                return False
            
            logger.debug(f"Intégrité vérifiée pour le vote {encrypted_vote_data['vote_token'][:8]}...")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification d'intégrité: {e}")
            return False
    
    def _generate_vote_token(self, vote_data: Dict) -> str:
        """Génère un token unique pour le vote"""
        token_data = f"{vote_data['election_id']}:{vote_data['candidate_id']}:{vote_data['timestamp']}:{secrets.token_hex(8)}"
        return hashlib.sha256(token_data.encode()).hexdigest()
    
    def _create_vote_signature(self, vote_data: Dict, vote_token: str) -> str:
        """Crée une signature numérique pour le vote"""
        try:
            # Données à signer
            signature_data = f"{vote_token}:{vote_data['election_id']}:{vote_data['timestamp']}"
            
            # Signer avec la clé publique de l'élection (simulation pour l'instant)
            signature = self.rsa_manager.sign_data(signature_data, self.election.public_key)
            
            # Enregistrer la signature
            DigitalSignature.objects.create(
                signed_data_hash=hashlib.sha256(signature_data.encode()).hexdigest(),
                signature_value=signature,
                algorithm='PSS',
                hash_algorithm='SHA256',
                context='vote_signing'
            )
            
            return signature
            
        except Exception as e:
            logger.error(f"Erreur lors de la création de signature: {e}")
            raise
    
    def _verify_vote_signature(self, encrypted_vote_data: Dict) -> bool:
        """Vérifie la signature numérique du vote"""
        try:
            # Reconstituer les données de signature
            signature_data = f"{encrypted_vote_data['vote_token']}:{self.election.id}:{encrypted_vote_data['timestamp']}"
            
            # Vérifier la signature
            return self.rsa_manager.verify_signature(
                signature_data,
                encrypted_vote_data['digital_signature'],
                self.election.public_key
            )
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de signature: {e}")
            return False
    
    def _anonymize_voter(self, voter_id: str, vote_token: str) -> str:
        """Anonymise l'électeur de manière irréversible"""
        # Utiliser un salt basé sur l'élection pour éviter les attaques par dictionnaire
        salt = f"{self.election.id}:{self.election.created_at.isoformat()}"
        voter_data = f"{voter_id}:{vote_token}:{salt}"
        return hashlib.sha256(voter_data.encode()).hexdigest()
    
    def _create_choice_hash(self, candidate_id: str, election_id: str) -> str:
        """Crée un hash du choix pour comptage anonyme"""
        choice_data = f"{election_id}:{candidate_id}"
        return hashlib.sha256(choice_data.encode()).hexdigest()
    
    def _create_validation_hash(self, vote_data: Dict) -> str:
        """Crée un hash de validation pour l'intégrité"""
        validation_data = json.dumps(vote_data, sort_keys=True)
        return hashlib.sha256(validation_data.encode()).hexdigest()
    
    def _verify_vote_integrity(self, decrypted_data: Dict, encrypted_data: Dict) -> bool:
        """Vérifie l'intégrité des données déchiffrées"""
        try:
            # Vérifier le hash de validation
            expected_hash = self._create_validation_hash(decrypted_data)
            actual_hash = encrypted_data.get('validation_hash')
            
            if expected_hash != actual_hash:
                return False
            
            # Vérifier la cohérence des métadonnées
            if decrypted_data['election_id'] != str(self.election.id):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _is_valid_vote_token(self, token: str) -> bool:
        """Vérifie le format du token de vote"""
        return isinstance(token, str) and len(token) == 64 and all(c in '0123456789abcdef' for c in token)
    
    def _log_crypto_operation(self, operation_type: str, data_size: int, processing_time: int, 
                            user_context: str, success: bool = True, error_message: str = ""):
        """Enregistre l'opération cryptographique pour audit"""
        try:
            # Récupérer la clé utilisée
            key_pair = None
            try:
                key_pair = KeyPair.objects.filter(
                    purpose='election',
                    is_active=True
                ).first()
            except:
                pass
            
            CryptographicOperation.log_operation(
                operation_type=operation_type,
                key_pair=key_pair,
                user=None,  # Anonyme pour la confidentialité
                data_size=data_size,
                processing_time=processing_time,
                success=success,
                error_message=error_message,
                algorithm='RSA-HYBRID',
                ip_address='127.0.0.1'  # À remplacer par l'IP réelle
            )
            
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement de l'opération crypto: {e}")


class VoteBatch:
    """
    Gestionnaire pour le traitement en lot des votes
    Exigence: Performance et sécurité pour de gros volumes
    """
    
    def __init__(self, election):
        self.election = election
        self.encryption = VoteEncryption(election)
        self.votes_batch = []
    
    def add_vote(self, candidate_choice: str, voter_id: str, additional_data: Dict = None):
        """Ajoute un vote au lot"""
        try:
            encrypted_vote = self.encryption.encrypt_vote(candidate_choice, voter_id, additional_data)
            self.votes_batch.append(encrypted_vote)
            logger.debug(f"Vote ajouté au lot: {encrypted_vote['vote_token'][:8]}...")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout du vote au lot: {e}")
            raise
    
    def process_batch(self) -> Dict[str, Any]:
        """Traite et valide le lot de votes"""
        try:
            if not self.votes_batch:
                return {'status': 'empty', 'processed': 0, 'errors': 0}
            
            processed = 0
            errors = 0
            
            for vote in self.votes_batch:
                try:
                    if self.encryption.verify_vote_integrity(vote):
                        processed += 1
                    else:
                        errors += 1
                        logger.warning(f"Vote avec intégrité compromise: {vote['vote_token'][:8]}...")
                        
                except Exception as e:
                    errors += 1
                    logger.error(f"Erreur lors de la validation du vote: {e}")
            
            # Créer un hash du lot pour intégrité
            batch_hash = self._create_batch_hash()
            
            # Enregistrer le hash du lot
            HashRecord.create_hash_record(
                data_identifier=f"vote_batch_{self.election.id}_{timezone.now().isoformat()}",
                data=batch_hash,
                purpose='vote_integrity',
                algorithm='SHA256'
            )
            
            result = {
                'status': 'completed',
                'processed': processed,
                'errors': errors,
                'total': len(self.votes_batch),
                'batch_hash': batch_hash
            }
            
            logger.info(f"Lot de votes traité: {processed} réussis, {errors} erreurs")
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement du lot: {e}")
            raise
    
    def _create_batch_hash(self) -> str:
        """Crée un hash du lot de votes pour intégrité"""
        batch_data = []
        for vote in self.votes_batch:
            batch_data.append(vote['vote_token'])
        
        batch_string = '|'.join(sorted(batch_data))
        return hashlib.sha256(batch_string.encode()).hexdigest()
    
    def clear_batch(self):
        """Vide le lot de votes"""
        self.votes_batch.clear()
        logger.debug("Lot de votes vidé")


class VoteDecryption:
    """
    Gestionnaire pour le déchiffrement sécurisé des votes (dépouillement)
    Exigence: Dépouillement sécurisé et transparent
    """
    
    def __init__(self, election, private_key: str):
        self.election = election
        self.private_key = private_key
        self.rsa_manager = RSAManager()
        self.decryption_log = []
    
    def decrypt_all_votes(self, encrypted_votes: list) -> Dict[str, Any]:
        """
        Déchiffre tous les votes pour le dépouillement
        
        Args:
            encrypted_votes: Liste des votes chiffrés
            
        Returns:
            Dict contenant les résultats du dépouillement
        """
        try:
            start_time = timezone.now()
            results = {}
            errors = []
            processed = 0
            
            for vote_data in encrypted_votes:
                try:
                    # Déchiffrer le vote
                    decrypted_vote = self.rsa_manager.decrypt_large_data(
                        vote_data['encrypted_data'],
                        self.private_key
                    )
                    
                    vote_content = json.loads(decrypted_vote)
                    candidate_id = vote_content['candidate_id']
                    
                    # Compter le vote
                    if candidate_id in results:
                        results[candidate_id] += 1
                    else:
                        results[candidate_id] = 1
                    
                    # Log pour audit
                    self.decryption_log.append({
                        'vote_token': vote_data['vote_token'],
                        'candidate_id': candidate_id,
                        'decrypted_at': timezone.now().isoformat()
                    })
                    
                    processed += 1
                    
                except Exception as e:
                    errors.append({
                        'vote_token': vote_data.get('vote_token', 'unknown'),
                        'error': str(e)
                    })
                    logger.error(f"Erreur lors du déchiffrement: {e}")
            
            # Créer le hash des résultats pour intégrité
            results_hash = self._create_results_hash(results)
            
            processing_time = (timezone.now() - start_time).total_seconds()
            
            decryption_result = {
                'results': results,
                'processed': processed,
                'errors': len(errors),
                'error_details': errors,
                'processing_time_seconds': processing_time,
                'results_hash': results_hash,
                'decryption_timestamp': timezone.now().isoformat()
            }
            
            logger.info(f"Dépouillement terminé: {processed} votes traités, {len(errors)} erreurs")
            return decryption_result
            
        except Exception as e:
            logger.error(f"Erreur lors du dépouillement: {e}")
            raise
    
    def _create_results_hash(self, results: Dict) -> str:
        """Crée un hash des résultats pour intégrité"""
        results_string = json.dumps(results, sort_keys=True)
        return hashlib.sha256(results_string.encode()).hexdigest()
    
    def get_audit_trail(self) -> list:
        """Retourne la trace d'audit du dépouillement"""
        return self.decryption_log.copy()


# Utilitaires de validation cryptographique

def validate_election_keys(election) -> bool:
    """
    Valide les clés cryptographiques d'une élection
    
    Args:
        election: Instance d'élection
        
    Returns:
        bool: True si les clés sont valides
    """
    try:
        rsa_manager = RSAManager()
        
        # Vérifier la clé publique
        key_info = rsa_manager.get_key_info(election.public_key, is_private=False)
        
        if key_info['key_size'] < 2048:
            logger.warning(f"Taille de clé insuffisante pour l'élection {election.id}: {key_info['key_size']}")
            return False
        
        if key_info['algorithm'] != 'RSA':
            logger.warning(f"Algorithme non supporté pour l'élection {election.id}: {key_info['algorithm']}")
            return False
        
        logger.info(f"Clés validées pour l'élection {election.id}")
        return True
        
    except Exception as e:
        logger.error(f"Erreur lors de la validation des clés: {e}")
        return False


def generate_election_keypair(election) -> Tuple[str, str]:
    """
    Génère une paire de clés pour une élection
    
    Args:
        election: Instance d'élection
        
    Returns:
        Tuple[str, str]: (clé_publique, clé_privée)
    """
    try:
        rsa_manager = RSAManager(key_size=2048)
        public_key, private_key = rsa_manager.generate_key_pair()
        
        # Enregistrer la clé dans le système de gestion des clés
        key_pair = KeyPair.generate_key_pair(
            name=f"Election_{election.id}",
            owner=election.created_by,
            purpose='election',
            key_size=2048,
            description=f"Clés pour l'élection: {election.title}"
        )
        
        logger.info(f"Paire de clés générée pour l'élection {election.id}")
        return public_key, private_key
        
    except Exception as e:
        logger.error(f"Erreur lors de la génération des clés: {e}")
        raise


def create_vote_receipt(encrypted_vote: Dict) -> Dict[str, Any]:
    """
    Crée un reçu de vote pour l'électeur
    
    Args:
        encrypted_vote: Vote chiffré
        
    Returns:
        Dict contenant le reçu de vote
    """
    try:
        receipt = {
            'receipt_id': secrets.token_hex(16),
            'vote_token': encrypted_vote['vote_token'][:16] + '...',  # Partiellement masqué
            'timestamp': encrypted_vote['timestamp'],
            'election_id': encrypted_vote.get('election_id', 'unknown'),
            'verification_code': hashlib.sha256(
                f"{encrypted_vote['vote_token']}:{encrypted_vote['timestamp']}".encode()
            ).hexdigest()[:12]
        }
        
        logger.debug(f"Reçu de vote créé: {receipt['receipt_id']}")
        return receipt
        
    except Exception as e:
        logger.error(f"Erreur lors de la création du reçu: {e}")
        raise