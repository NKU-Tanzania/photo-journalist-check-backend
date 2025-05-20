from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.http import HttpResponseRedirect
from django.utils.html import format_html
from django.urls import reverse, path
from .models import CustomUser, UploadedImage
from .views import admin_metadata_view, image_gallery_view, verify_image_view, admin_image_download


class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('username', 'email', 'phone_number', 'id_card', 'has_public_key', 'is_staff', 'is_superuser')
    search_fields = ('username', 'email')
    list_filter = ('is_staff', 'is_superuser')

    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('phone_number', 'id_card', 'public_key')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': ('phone_number', 'id_card')}),
    )

    def has_public_key(self, obj):
        return bool(obj.public_key)

    has_public_key.boolean = True
    has_public_key.short_description = 'Has Public Key'


admin.site.register(CustomUser, CustomUserAdmin)


@admin.register(UploadedImage)
class UploadedImageAdmin(admin.ModelAdmin):
    list_display = ('user', 'truncated_hash_value', 'truncated_calculated_hash', 'verification_status', 'uploaded_at',
                    'verification_actions', 'view_metadata_link')
    list_filter = ('verified', 'uploaded_at')
    readonly_fields = ('metadata_display', 'hash_value', 'verification_status', 'verification_details', 'gallery_view')

    # Disable the add button
    def has_add_permission(self, request):
        return False

    # Redirect changelist view to our custom gallery view
    def changelist_view(self, request, extra_context=None):
        # Redirect to our custom gallery view
        return HttpResponseRedirect(reverse('admin-image-gallery'))

    def truncated_hash_value(self, obj):
        return format_html('<div style="max-width:150px; word-wrap:break-word;">{}</div>', obj.hash_value)

    truncated_hash_value.short_description = 'Client Hash Value'

    def truncated_calculated_hash(self, obj):
        return format_html('<div style="max-width:150px; word-wrap:break-word;">{}</div>', obj.calculated_hash_value)

    truncated_calculated_hash.short_description = 'Server Hash Value'

    def view_metadata_link(self, obj):
        """Creates a clickable 'View More' link to display metadata in a detailed view."""
        url = reverse('admin-image-metadata', kwargs={'image_id': obj.id})
        return format_html('<a href="{}" target="_blank">View Info</a>', url)

    view_metadata_link.short_description = 'Info'

    def verification_status(self, obj):
        if obj.verified:
            return format_html('<span style="color: green; font-weight: bold;">✓ Verified 🙂</span>')
        else:
            return format_html('<span style="color: red; font-weight: bold;">✗ Not Verified 😞</span>')

    verification_status.short_description = 'Verification'

    def verification_actions(self, obj):
        if obj.verified:
            download_url = reverse('admin-image-download', kwargs={'image_id': obj.id})
            return format_html(
                '<a class="button" href="{}" target="_blank">Download</a>',
                download_url
            )
        else:
            return format_html(
                '<a class="button" href="javascript:void(0);" onclick="verifyImage({})">Verify Now</a>',
                obj.id
            )

    verification_actions.short_description = 'Actions'

    def gallery_view(self, obj):
        """Link back to gallery view"""
        url = reverse('admin-image-gallery')
        return format_html('<a href="{}">Back to Gallery</a>', url)

    gallery_view.short_description = ''

    def metadata_display(self, obj):
        """Format metadata as readable HTML"""
        if not obj.metadata:
            return "No metadata"

        html = ['<table style="width:100%">']
        for key, value in obj.metadata.items():
            html.append(f'<tr><th style="text-align:left;padding:5px;background:#f0f0f0;">{key}</th>'
                        f'<td style="padding:5px;">{value}</td></tr>')
        html.append('</table>')
        return format_html(''.join(html))

    metadata_display.short_description = 'Image Metadata'

    def verification_details(self, obj):
        """Display detailed verification information"""
        if obj.verified:
            return format_html(
                '<div style="padding:10px;background:#e6ffe6;border:1px solid #99cc99;">'
                '<h3 style="margin-top:0;">✓ Image Verified</h3>'
                '<p>This image has been cryptographically verified as authentic.</p>'
                '<p><strong>Hash:</strong> {}</p>'
                '</div>',
                obj.hash_value
            )
        else:
            hash_match = obj.hash_value == obj.calculated_hash_value
            status_text = "Hash values do not match" if not hash_match else "Not yet verified"

            return format_html(
                '<div style="padding:10px;background:#ffe6e6;border:1px solid #cc9999;">'
                '<h3 style="margin-top:0;">✗ Not Verified</h3>'
                '<p>{}</p>'
                '<p><strong>Stored Hash:</strong> {}</p>'
                '<p><strong>Calculated Hash:</strong> {}</p>'
                '<a class="button" href="javascript:void(0);" onclick="verifyImage({})">Verify Now</a>'
                '</div>',
                status_text,
                obj.hash_value,
                obj.calculated_hash_value or "Not calculated yet",
                obj.id
            )

    # Add JavaScript for image verification
    class Media:
        js = ('js/verification.js',)

    # Add custom view for verification
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('image/<int:image_id>/metadata/',
                 self.admin_site.admin_view(admin_metadata_view),
                 name='admin-image-metadata'),
            path('verify-image/<int:image_id>/',
                 self.admin_site.admin_view(verify_image_view),
                 name='admin-verify-image'),
            path('image/<int:image_id>/download/',
                 self.admin_site.admin_view(admin_image_download),
                 name='admin-image-download'),
            path('image-gallery/',
                 self.admin_site.admin_view(image_gallery_view),
                 name='admin-image-gallery'),
        ]
        return custom_urls + urls


# Only keep this line from the previous URL customization
admin.site.index_title = ""  # Remove "Site administration"
admin.site.site_header = ""