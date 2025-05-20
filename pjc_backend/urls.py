from django.contrib import admin
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from .views import (
    ImageUploadView,
    ImageVerificationView,
    ImageDownloadView,
    UserRegistrationView,
    PublicKeyView,
    CustomTokenObtainPairView,
    LogoutView,
    PublicKeySetupView,
    BulkImageDownloadView,
    admin_image_download,
    admin_dashboard,
    get_dashboard_counts,
    image_gallery_view,
    admin_metadata_view,
    verify_image_view,
)

from rest_framework_simplejwt.views import TokenRefreshView

# Remove the problematic admin URLs override
# admin_urls = [
#     path('dashboard/', admin_dashboard, name='admin-dashboard'),
#     path('image/<int:image_id>/metadata/', admin_metadata_view, name='admin-image-metadata'),
#     path('image/<int:image_id>/download/', admin_image_download, name='admin-image-download'),
# ]
#
# admin.site.get_urls = lambda: admin_urls + list(admin.site.urls)

# We can still set the index_template
admin.site.index_template = 'admin/dashboard.html'

urlpatterns = [
    # Admin dashboard URL
    path('admin/dashboard/', admin.site.admin_view(admin_dashboard), name='admin-dashboard'),

    # Add these custom admin URLs BEFORE the admin.site.urls pattern
    path('admin/image-gallery/', admin.site.admin_view(image_gallery_view), name='admin-image-gallery'),
    path('admin/image/<int:image_id>/metadata/', admin.site.admin_view(admin_metadata_view),
         name='admin-image-metadata'),
    path('admin/verify-image/<int:image_id>/', admin.site.admin_view(verify_image_view), name='admin-verify-image'),
    path('admin/image/<int:image_id>/download/', admin.site.admin_view(admin_image_download),
         name='admin-image-download'),

    # The standard admin URLs - this should be AFTER your custom admin URLs
    path('admin/', admin.site.urls),

    # Authentication
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('logout/', LogoutView.as_view(), name='auth_logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Dashboard API
    path('dashboard-counts/', get_dashboard_counts, name='dashboard-counts'),

    # Image operations
    path('upload/', ImageUploadView.as_view(), name='image-upload'),
    path('verify/<int:image_id>/', ImageVerificationView.as_view(), name='image-verify'),
    path('download/<int:image_id>/', ImageDownloadView.as_view(), name='image-download'),
    path('download/all/', BulkImageDownloadView.as_view(), name='bulk-image-download'),

    # User operations
    path('register/', UserRegistrationView.as_view(), name='user-register'),
    path('users/public-key/', PublicKeyView.as_view(), name='current-user-public-key'),
    path('users/setup-public-key/', PublicKeySetupView.as_view(), name='setup-public-key'),
    path('users/<int:user_id>/public-key/', PublicKeyView.as_view(), name='user-public-key'),
]