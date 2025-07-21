# dashboard/views.py - Vues pour les tableaux de bord de GalSecVote
"""
Vues pour l'interface de tableau de bord administratif
Exigence: Interface d'administration personnalisable et monitoring
"""

import json
import logging
from datetime import datetime, timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib import messages
from django.views.generic import TemplateView, ListView, DetailView, CreateView, UpdateView, DeleteView
from django.http import JsonResponse, HttpResponse, Http404
from django.urls import reverse_lazy
from django.utils import timezone
from django.db.models import Count, Q, Avg, Max, Min
from django.core.exceptions import PermissionDenied
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.csrf import csrf_exempt

from .models import Dashboard, DashboardWidget, DashboardWidgetConfig, SystemMetric, Alert, SystemStatus
from accounts.models import User
from audit.models import AuditLog

logger = logging.getLogger('dashboard.views')


class DashboardHomeView(LoginRequiredMixin, TemplateView):
    """
    Vue du tableau de bord principal
    Exigence: Interface d'administration centralisée
    """
    template_name = 'dashboard/home.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Charger le dashboard par défaut de l'utilisateur ou le système
        user_dashboard = Dashboard.objects.filter(
            owner=self.request.user, 
            is_default=True, 
            is_active=True
        ).first()
        
        if not user_dashboard:
            # Charger le dashboard système par défaut
            user_dashboard = Dashboard.objects.filter(
                is_system_dashboard=True,
                is_active=True
            ).first()
        
        context['dashboard'] = user_dashboard
        
        if user_dashboard:
            # Métriques du tableau de bord
            context['metrics'] = self._get_dashboard_metrics()
            # Widgets configurés
            context['widgets'] = self._get_user_widgets(user_dashboard)
        
        return context
    
    def _get_dashboard_metrics(self):
        """Récupère les métriques principales du système"""
        return {
            'total_users': User.objects.filter(is_active=True).count(),
            'active_elections': 0,  # À implémenter selon vos modèles
            'recent_alerts': Alert.objects.filter(is_resolved=False).count(),
            'system_health': 'good'  # À implémenter selon votre logique
        }
    
    def _get_user_widgets(self, dashboard):
        """Récupère les widgets configurés pour le dashboard"""
        return DashboardWidgetConfig.objects.filter(
            dashboard=dashboard,
            is_visible=True
        ).select_related('widget').order_by('position_y', 'position_x')


class CustomDashboardListView(LoginRequiredMixin, ListView):
    """
    Liste des tableaux de bord personnalisés de l'utilisateur
    """
    model = Dashboard
    template_name = 'dashboard/custom_list.html'
    context_object_name = 'dashboards'
    paginate_by = 20
    
    def get_queryset(self):
        return Dashboard.objects.filter(
            Q(owner=self.request.user) | Q(shared_with_users=self.request.user),
            is_active=True
        ).distinct().order_by('-updated_at')


class CustomDashboardDetailView(LoginRequiredMixin, DetailView):
    """
    Vue détaillée d'un tableau de bord personnalisé
    """
    model = Dashboard
    template_name = 'dashboard/custom_detail.html'
    context_object_name = 'dashboard'
    
    def get_object(self):
        dashboard = super().get_object()
        if not dashboard.can_user_view(self.request.user):
            raise PermissionDenied("Vous n'avez pas les permissions pour voir ce tableau de bord")
        
        # Incrémenter le compteur de vues
        dashboard.increment_view()
        return dashboard


class CreateDashboardView(LoginRequiredMixin, CreateView):
    """
    Création d'un nouveau tableau de bord
    """
    model = Dashboard
    fields = ['name', 'description', 'is_shared', 'theme', 'refresh_interval']
    template_name = 'dashboard/create_dashboard.html'
    success_url = reverse_lazy('dashboard:custom_list')
    
    def form_valid(self, form):
        form.instance.owner = self.request.user
        response = super().form_valid(form)
        
        # Log de l'action
        AuditLog.log_action(
            user=self.request.user,
            action='dashboard_create',
            resource='dashboard',
            details={'dashboard_id': str(self.object.id), 'name': self.object.name}
        )
        
        messages.success(self.request, f'Tableau de bord "{self.object.name}" créé avec succès.')
        return response


class EditDashboardView(LoginRequiredMixin, UpdateView):
    """
    Modification d'un tableau de bord existant
    """
    model = Dashboard
    fields = ['name', 'description', 'is_shared', 'theme', 'refresh_interval']
    template_name = 'dashboard/edit_dashboard.html'
    
    def get_object(self):
        dashboard = super().get_object()
        if dashboard.owner != self.request.user and not self.request.user.is_staff:
            raise PermissionDenied("Vous ne pouvez modifier que vos propres tableaux de bord")
        return dashboard
    
    def get_success_url(self):
        return reverse_lazy('dashboard:custom_detail', kwargs={'pk': self.object.pk})


class DeleteDashboardView(LoginRequiredMixin, DeleteView):
    """
    Suppression d'un tableau de bord
    """
    model = Dashboard
    template_name = 'dashboard/delete_dashboard.html'
    success_url = reverse_lazy('dashboard:custom_list')
    
    def get_object(self):
        dashboard = super().get_object()
        if dashboard.owner != self.request.user and not self.request.user.is_staff:
            raise PermissionDenied("Vous ne pouvez supprimer que vos propres tableaux de bord")
        return dashboard


class WidgetListView(LoginRequiredMixin, ListView):
    """
    Liste des widgets disponibles
    """
    model = DashboardWidget
    template_name = 'dashboard/widget_list.html'
    context_object_name = 'widgets'
    
    def get_queryset(self):
        return DashboardWidget.objects.filter(is_active=True).order_by('name')


class WidgetDetailView(LoginRequiredMixin, DetailView):
    """
    Vue détaillée d'un widget
    """
    model = DashboardWidget
    template_name = 'dashboard/widget_detail.html'
    context_object_name = 'widget'


class SystemMetricsView(LoginRequiredMixin, PermissionRequiredMixin, TemplateView):
    """
    Vue des métriques système
    """
    template_name = 'dashboard/system_metrics.html'
    permission_required = 'dashboard.view_systemmetric'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Métriques récentes (dernières 24h)
        since = timezone.now() - timedelta(hours=24)
        context['recent_metrics'] = SystemMetric.objects.filter(
            timestamp__gte=since
        ).order_by('-timestamp')[:100]
        
        return context


class AlertManagementView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
    """
    Gestion des alertes système
    """
    model = Alert
    template_name = 'dashboard/alert_management.html'
    context_object_name = 'alerts'
    permission_required = 'dashboard.view_alert'
    paginate_by = 50
    
    def get_queryset(self):
        return Alert.objects.filter(
            is_resolved=False
        ).order_by('-created_at')


class LiveMonitoringView(LoginRequiredMixin, PermissionRequiredMixin, TemplateView):
    """
    Monitoring en temps réel
    """
    template_name = 'dashboard/live_monitoring.html'
    permission_required = 'dashboard.view_systemstatus'


class DashboardSettingsView(LoginRequiredMixin, TemplateView):
    """
    Paramètres du tableau de bord
    """
    template_name = 'dashboard/settings.html'


class NotificationSettingsView(LoginRequiredMixin, TemplateView):
    """
    Paramètres de notifications
    """
    template_name = 'dashboard/notification_settings.html'


# Vues API pour AJAX
@login_required
def metrics_api(request):
    """API pour les métriques en temps réel"""
    if not request.user.has_perm('dashboard.view_systemmetric'):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    # Dernières métriques
    metrics = SystemMetric.objects.all()[:10]
    data = [{
        'name': metric.name,
        'value': metric.value,
        'timestamp': metric.timestamp.isoformat()
    } for metric in metrics]
    
    return JsonResponse({'metrics': data})


@login_required
def alerts_api(request):
    """API pour les alertes actives"""
    if not request.user.has_perm('dashboard.view_alert'):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    alerts = Alert.objects.filter(is_resolved=False)[:10]
    data = [{
        'id': alert.id,
        'title': alert.title,
        'severity': alert.severity,
        'created_at': alert.created_at.isoformat()
    } for alert in alerts]
    
    return JsonResponse({'alerts': data})


@login_required
def system_status_api(request):
    """API pour le statut système"""
    if not request.user.has_perm('dashboard.view_systemstatus'):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        status = SystemStatus.objects.latest('timestamp')
        data = {
            'status': status.status,
            'timestamp': status.timestamp.isoformat(),
            'details': status.details
        }
    except SystemStatus.DoesNotExist:
        data = {
            'status': 'unknown',
            'timestamp': timezone.now().isoformat(),
            'details': {}
        }
    
    return JsonResponse(data)


@login_required
def dashboard_data_api(request, dashboard_id):
    """API pour les données d'un dashboard spécifique"""
    try:
        dashboard = Dashboard.objects.get(id=dashboard_id)
        if not dashboard.can_user_view(request.user):
            return JsonResponse({'error': 'Permission denied'}, status=403)
        
        # Données basiques du dashboard
        data = {
            'id': str(dashboard.id),
            'name': dashboard.name,
            'widgets': []
        }
        
        # Ajouter les widgets
        for widget_config in dashboard.dashboardwidgetconfig_set.filter(is_visible=True):
            widget_data = {
                'id': str(widget_config.widget.id),
                'name': widget_config.widget.name,
                'type': widget_config.widget.widget_type,
                'position': {
                    'x': widget_config.position_x,
                    'y': widget_config.position_y,
                    'width': widget_config.width,
                    'height': widget_config.height
                }
            }
            data['widgets'].append(widget_data)
        
        return JsonResponse(data)
        
    except Dashboard.DoesNotExist:
        return JsonResponse({'error': 'Dashboard not found'}, status=404)


@login_required
@permission_required('dashboard.change_alert')
def acknowledge_alert(request, pk):
    """Acquitter une alerte"""
    alert = get_object_or_404(Alert, pk=pk)
    alert.is_acknowledged = True
    alert.acknowledged_by = request.user
    alert.acknowledged_at = timezone.now()
    alert.save()
    
    # Log de l'action
    AuditLog.log_action(
        user=request.user,
        action='alert_acknowledge',
        resource='alert',
        details={'alert_id': pk}
    )
    
    messages.success(request, 'Alerte acquittée avec succès.')
    return redirect('dashboard:alert_management')


@login_required
@permission_required('dashboard.change_alert')
def resolve_alert(request, pk):
    """Résoudre une alerte"""
    alert = get_object_or_404(Alert, pk=pk)
    alert.is_resolved = True
    alert.resolved_by = request.user
    alert.resolved_at = timezone.now()
    alert.save()
    
    # Log de l'action
    AuditLog.log_action(
        user=request.user,
        action='alert_resolve',
        resource='alert',
        details={'alert_id': pk}
    )
    
    messages.success(request, 'Alerte résolue avec succès.')
    return redirect('dashboard:alert_management')


@login_required
@permission_required('dashboard.view_systemmetric')
def export_metrics(request):
    """Exporter les métriques système"""
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="system_metrics.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'Name', 'Value', 'Unit'])
    
    # Dernières 1000 métriques
    metrics = SystemMetric.objects.all().order_by('-timestamp')[:1000]
    for metric in metrics:
        writer.writerow([
            metric.timestamp.isoformat(),
            metric.name,
            metric.value,
            getattr(metric, 'unit', '')
        ])
    
    return response