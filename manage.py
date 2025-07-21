#!/usr/bin/env python
# manage.py - Script de gestion Django pour GalSecVote
"""
Script de ligne de commande Django pour les tâches administratives.
Système de vote électronique sécurisé - GalSecVote
"""

import os
import sys

def main():
    """Exécute les tâches administratives."""
    
    # Configuration par défaut du module de paramètres Django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'galsecvote.settings')
    
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Impossible d'importer Django. Êtes-vous sûr qu'il est installé et "
            "disponible dans votre variable d'environnement PYTHONPATH ? "
            "Avez-vous oublié d'activer un environnement virtuel ?"
        ) from exc
    
    # Messages d'aide pour les développeurs
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        # Messages spéciaux pour certaines commandes
        if command == 'runserver':
            print("🚀 Démarrage du serveur de développement GalSecVote...")
            print("📱 Interface d'administration: http://127.0.0.1:8000/admin/")
            print("🗳️  Interface de vote: http://127.0.0.1:8000/vote/")
            print("📊 Tableau de bord: http://127.0.0.1:8000/dashboard/")
            print("🔍 Audit: http://127.0.0.1:8000/audit/")
            print("🔐 Authentification: http://127.0.0.1:8000/login/")
            print("⚠️  Mode: DÉVELOPPEMENT - Ne pas utiliser en production !")
            print()
        
        elif command == 'migrate':
            print("🗄️  Exécution des migrations de base de données...")
        
        elif command == 'createsuperuser':
            print("👨‍💼 Création d'un compte administrateur...")
            print("ℹ️  Ce compte aura tous les privilèges dans GalSecVote")
        
        elif command == 'collectstatic':
            print("📁 Collecte des fichiers statiques...")
        
        elif command == 'test':
            print("🧪 Exécution des tests de sécurité...")
    
    # Exécuter la commande Django
    execute_from_command_line(sys.argv)

if __name__ == '__main__':
    main()