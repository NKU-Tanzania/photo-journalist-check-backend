"""
URL configuration for siu_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.conf import settings
from django.conf.urls.static import static

from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.http import require_GET

# from django.urls import path
# from django.views.generic import RedirectView
# from siu_backend.authentication.views import admin_dashboard, admin_metadata_view, admin_image_download

# Custom admin URLs
# admin_urls = [
#     path('dashboard/', admin_dashboard, name='admin-dashboard'),
#     path('image/<int:image_id>/metadata/', admin_metadata_view, name='admin-image-metadata'),
#     path('image/<int:image_id>/download/', admin_image_download, name='admin-image-download'),
# ]
#
# # Add the custom URLs to the admin site
# admin.site.get_urls = lambda: admin_urls + list(admin.site.urls)
#
# # Override the default admin index
# admin.site.index_template = 'admin/dashboard.html'

urlpatterns = [
    path('admin/', admin.site.urls),
    # path('', RedirectView.as_view(url='admin/', permanent=False)),
    path('auth/', include('pjc_backend.urls')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]



if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)