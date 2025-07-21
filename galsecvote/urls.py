# galsecvote/urls.py - Configuration URL principale pour GalSecVote
"""
Configuration URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

# Gestionnaires d'erreurs personnalisés
handler400 = 'galsecvote.views.bad_request'
handler403 = 'galsecvote.views.permission_denied'
handler404 = 'galsecvote.views.page_not_found'
handler500 = 'galsecvote.views.server_error'

urlpatterns = [
    # Administration Django
    path('admin/', admin.site.urls),
    
    # Page d'accueil - redirection vers les élections
    path('', RedirectView.as_view(pattern_name='vote:elections_list', permanent=False), name='home'),
    
    # Applications principales
    path('', include('accounts.urls')),  # URLs d'authentification à la racine
    path('vote/', include('vote.urls')),  # Système de vote
    path('audit/', include('audit.urls')),  # Interface d'audit
    path('dashboard/', include('dashboard.urls')),  # Tableau de bord (si existant)
]

# Servir les fichiers statiques en développement
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Configuration du site d'administration
admin.site.site_header = "GalSecVote Administration"
admin.site.site_title = "GalSecVote Admin"
admin.site.index_title = "Administration du système de vote sécurisé"