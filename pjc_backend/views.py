import logging
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from .serializers import CustomUserSerializer
from .serializers import UploadedImageSerializer
from rest_framework.response import Response
from .models import CustomUser, UploadedImage
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
import base64
import json
from django.utils import timezone
from rest_framework import status
import os
from django.http import FileResponse, Http404, HttpResponse
from django.views.decorators.http import require_GET
from django.shortcuts import render, get_object_or_404
from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Count
from datetime import timedelta, datetime
from django.http import JsonResponse
from django.contrib.admin.views.decorators import staff_member_required
from django.http import JsonResponse, HttpResponse, FileResponse
from django.core.paginator import Paginator
from django.views.decorators.http import require_POST
from django.urls import path, reverse
import io
from django.conf import settings
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rest_framework_simplejwt.tokens import RefreshToken
from cryptography.hazmat.primitives import serialization

# this is the endpoint for sending counts to admin panel
def get_dashboard_counts(request):
    # Get counts
    user_count = CustomUser.objects.count()
    image_count = UploadedImage.objects.count()
    verified_count = UploadedImage.objects.filter(verified=True).count()

    # Calculate active users (users who uploaded in the last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    active_users = CustomUser.objects.filter(
        uploadedimage__uploaded_at__gte=thirty_days_ago
    ).distinct().count()

    # Calculate verification percentage
    verification_percentage = 0
    if image_count > 0:
        verification_percentage = round((verified_count / image_count) * 100, 1)

    return JsonResponse({
        'user_count': user_count,
        'image_count': image_count,
        'verified_count': verified_count,
        'active_users': active_users,
        'inactive_users': user_count - active_users,
        'verification_percentage': verification_percentage,
        'unverified_count': image_count - verified_count,
    })


# Gallery view that replaces the default admin list view
@staff_member_required
def image_gallery_view(request):
    image_list = UploadedImage.objects.all().order_by('-uploaded_at')

    # Filter by verification status
    verification_status = request.GET.get('status')
    if verification_status == 'verified':
        image_list = image_list.filter(verified=True)
    elif verification_status == 'unverified':
        image_list = image_list.filter(verified=False)

    # Filter by user
    user_filter = request.GET.get('user')
    if user_filter:
        image_list = image_list.filter(user__username__icontains=user_filter)

    # Pagination
    paginator = Paginator(image_list, 12)  # Show 12 images per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'title': 'Image Verification Gallery',
        'image_list': page_obj,
        'page_obj': page_obj,
        'verification_status': verification_status,
        'user_filter': user_filter,
    }

    return render(request, 'admin/custom_gallery.html', context)


# Detailed metadata view for an image
@staff_member_required
def admin_metadata_view(request, image_id):
    image = get_object_or_404(UploadedImage, id=image_id)

    context = {
        'title': f'Image Metadata: {image.user.username}',
        'image': image,
        'hash_match': image.hash_value == image.calculated_hash_value,
    }

    return render(request, 'admin/image_metadata.html', context)


# Image verification API endpoint
@staff_member_required
@require_POST
def verify_image_view(request, image_id):
    image = get_object_or_404(UploadedImage, id=image_id)

    try:
        # Recalculate hash to verify
        image_data = image.original_image.read()
        calculated_hash = hashlib.sha256(image_data).hexdigest()

        # Compare with stored hash
        if calculated_hash == image.hash_value:
            image.verified = True
            image.calculated_hash_value = calculated_hash
            image.save()
            return JsonResponse({'success': True, 'message': 'Image successfully verified'})
        else:
            return JsonResponse({
                'success': False,
                'message': 'Verification failed: Hash mismatch',
                'stored_hash': image.hash_value,
                'calculated_hash': calculated_hash
            })
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error during verification: {str(e)}'})


# Image download endpoint
@staff_member_required
def admin_image_download(request, image_id):
    image = get_object_or_404(UploadedImage, id=image_id)

    if not image.verified:
        return HttpResponse("This image has not been verified and cannot be downloaded.", status=403)

    try:
        image_file = image.original_image
        return FileResponse(image_file, as_attachment=True, filename=f"verified_{image_id}.jpg")
    except Exception as e:
        return HttpResponse(f"Error downloading file: {str(e)}", status=500)

@staff_member_required
def admin_dashboard(request):
    # User stats
    user_count = CustomUser.objects.count()
    first_user = CustomUser.objects.order_by('date_joined').first()
    first_user_date = first_user.date_joined if first_user else timezone.now()

    # Active users (logged in last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    active_users = CustomUser.objects.filter(last_login__gte=thirty_days_ago).count()
    inactive_users = user_count - active_users

    # Image stats
    image_count = UploadedImage.objects.count()
    first_image = UploadedImage.objects.order_by('uploaded_at').first()
    first_image_date = first_image.uploaded_at if first_image else timezone.now()

    verified_count = UploadedImage.objects.filter(verified=True).count()
    unverified_count = image_count - verified_count
    verification_percentage = int((verified_count / image_count) * 100) if image_count > 0 else 0

    # Recent activity
    seven_days_ago = timezone.now() - timedelta(days=7)
    recent_activity_count = UploadedImage.objects.filter(uploaded_at__gte=seven_days_ago).count()

    # Monthly chart data
    last_6_months = timezone.now() - timedelta(days=180)
    monthly_data = (
        UploadedImage.objects
        .filter(uploaded_at__gte=last_6_months)
        .extra({'month': "date_trunc('month', uploaded_at)"})
        .values('month')
        .annotate(count=Count('id'))
        .order_by('month')
    )

    # Format data for Chart.js
    chart_labels = []
    chart_data = []

    for entry in monthly_data:
        month = entry['week'].strftime('%b %y')
        chart_labels.append(month)
        chart_data.append(entry['count'])

    # If no data found, generate a default 6-month range
    if not chart_labels:
        current = timezone.now()
        for i in range(6):
            month = (current - timedelta(days=30 * i)).strftime('%b %y')
            chart_labels.insert(0, month)
            chart_data.insert(0, 0)
    else:
        # Ensure we have at least 6 months of data
        while len(chart_labels) < 6:
            # Add empty months before the earliest existing month
            earliest_month = chart_labels[0]
            earliest_datetime = timezone.datetime.strptime(earliest_month, '%b %y')
            new_month = (earliest_datetime - timedelta(days=30)).strftime('%b %y')
            chart_labels.insert(0, new_month)
            chart_data.insert(0, 0)

    context = {
        'user_count': user_count,
        'first_user_date': first_user_date,
        'active_users': active_users,
        'inactive_users': inactive_users,
        'image_count': image_count,
        'first_image_date': first_image_date,
        'verified_count': verified_count,
        'unverified_count': unverified_count,
        'verification_percentage': verification_percentage,
        'recent_activity_count': recent_activity_count,
        'chart_labels': json.dumps(chart_labels),
        'chart_data': json.dumps(chart_data),
    }

    return render(request, 'admin/dashboard.html', context)

# Set up logging
logger = logging.getLogger(__name__)

# Login API
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom token view that checks if user has a public key before issuing tokens
    """

    def post(self, request, *args, **kwargs):
        # First validate the credentials with the serializer
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            # Return the original error response if validation fails
            return super().post(request, *args, **kwargs)

        # Get the user from the serializer
        user = serializer.user

        # Check if user has a public key
        if not user.public_key:
            return Response(
                {"error": "Public key not found for this user", "requires_key": True},
                status=status.HTTP_404_NOT_FOUND
            )

        # Update last_login for the user
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        response = super().post(request, *args, **kwargs)

        # Add the server's public key to the response data
        response.data['server_public_key'] = user.server_public_key

        response.data['user_id'] = user.id
        # Log that we're sending the server's public key
        logger.info(f"Sending server public key to user {user.username} during login")
        logger.debug(f"Public key length: {len(user.server_public_key)}, First 20 chars: {user.server_public_key[:20]}")
        # Return the token response
        return response
    
class LogoutView(APIView):
    """
    API endpoint for user logout
    POST /auth/logout/ - Blacklist the user's refresh token
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Get the refresh token from request data
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Blacklist the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(
                {"message": "Logout successful"},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
class UserRegistrationView(APIView):
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                "message": "User registered successfully",
                "user_id": user.id,
                "username": user.username
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class PublicKeyView(APIView):
    """
    Endpoint for receiving a user's public key and generating a server-side RSA key pair.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Receive user's public key and generate a server-side key pair"""
        user = request.user

        if 'public_key' not in request.data:
            return Response(
                {"error": "Public key is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Store the user's public key
        user.public_key = request.data['public_key']

        # Generate a new server-side key pair for this user
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Get the public key from the private key
        public_key = private_key.public_key()

        # Serialize the private key in PEM format (keep this for server-side use)
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize the public key in DER format (X.509)
        der_public = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Base64 encode the DER format for frontend compatibility
        base64_public = base64.b64encode(der_public).decode('utf-8')

        # Store both keys
        user.server_private_key = pem_private.decode('utf-8')
        user.server_public_key = base64_public
        user.save()

        # Return the server's public key to the client
        response_data = {
            "message": "Public key received and server keys generated successfully",
            "user_id": user.id,
            "server_public_key": user.server_public_key
        }

        return Response(response_data, status=status.HTTP_201_CREATED)

class PublicKeySetupView(APIView):
    """
    Endpoint for initially setting up a user's public key without requiring authentication.
    Only usable before the first login.
    """

    # No authentication required for this endpoint

    def post(self, request):
        """Receive and save a user's public key during initial setup"""
        if 'user_id' not in request.data or 'public_key' not in request.data:
            return Response(
                {"error": "User ID and public key are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        user_id = request.data['user_id']

        try:
            user = CustomUser.objects.get(id=user_id)

            # Only allow setting public key if it hasn't been set before
            if user.public_key:
                return Response(
                    {"error": "Public key already exists. Use the authenticated endpoint to update."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            # Store the user's public key
            user.public_key = request.data['public_key']

            # Generate server side key-pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            public_key = private_key.public_key()

            # Serialize the private key in PEM format (keep this for server-side use)
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Serialize the public key in DER format (X.509)
            der_public = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Base64 encode the DER format for frontend compatibility
            base64_public = base64.b64encode(der_public).decode('utf-8')

            user.server_private_key = pem_private.decode('utf-8')
            user.server_public_key = base64_public
            user.save()

            return Response({
                "message": "Public key set and server keys generated successfully",
                "user_id": user.id,
                "server_public_key": user.server_public_key
            }, status=status.HTTP_201_CREATED)

        except CustomUser.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )

class ImageUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            # Log request details for debugging
            logger.info(f"Received image upload request from user {request.user.username}")

            # Check if user has a public key
            user = request.user
            if not user.public_key or not user.server_public_key:
                return Response(
                    {"error": "User doesn't have required keys. Set a public key before uploading images."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Check if required parameters are in the request
            if 'image' not in request.FILES or 'aes_key' not in request.data:
                return Response(
                    {"error": "Both image file and aes_key are required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            image_file = request.FILES['image']
            aes_key = base64.b64decode(request.data.get('aes_key'))
            provided_hash = request.data.get('hash_value')

            # Process metadata if provided
            metadata = {}
            if 'metadata' in request.data:
                try:
                    metadata = json.loads(request.data.get('metadata'))
                    logger.info(f"Received metadata: {metadata}")

                    # Get client IP and add it directly to metadata
                    client_ip = self.get_client_ip(request)
                    metadata['client_ip_address'] = client_ip

                    # Add server-side timestamp
                    metadata['server_received_time'] = timezone.now().isoformat()

                    # Debug log to ensure we can see if location data is included
                    if 'location' in metadata:
                        logger.info(f"Location data received: {metadata['location']}")
                    else:
                        logger.warning("No location data in client metadata")
                except json.JSONDecodeError:
                    logger.warning(f"Invalid metadata JSON received: {request.data.get('metadata')}")
                    metadata = {
                        "error": "Invalid metadata format",
                        "ip_address": self.get_client_ip(request)  # Still add IP even if other metadata fails
                    }

            caption = request.data.get('caption', '')



            # Use the model's class method to handle the upload
            upload, computed_hash = UploadedImage.upload_image(
                user,
                image_file,
                aes_key,
                provided_hash=provided_hash,
                metadata=metadata,
                caption = caption
            )

            # Attempt to verify the image
            verified, message = upload.verify_image()
            logger.info(f"Verification result: {verified}, Message: {message}")

            # Serialize the response data
            serializer = UploadedImageSerializer(upload)

            # Ensure the metadata is included in the response
            response_data = {
                "message": "Image uploaded successfully!",
                "data": serializer.data,
                "verification": {
                    "status": verified,
                    "message": message
                },
                "metadata": upload.metadata, 
                "received_client_metadata": metadata  # Include the original metadata for debugging
            }

            # Add download URL if verified
            if verified and upload.original_image:
                response_data["download_url"] = request.build_absolute_uri(upload.original_image.url)

            return Response(response_data, status=status.HTTP_201_CREATED)

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Error in image upload: {str(e)}")
            logger.error(error_trace)
            return Response(
                {"error": f"Server error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get_client_ip(self, request):
        """Get the client's IP address from the request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

# Image verification API
class ImageVerificationView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, image_id):
        try:
            image = UploadedImage.objects.get(id=image_id)

            # Check if user has permission to verify this image
            if image.user != request.user and not request.user.is_staff:
                return Response({"error": "Not authorized to verify this image"},
                                status=status.HTTP_403_FORBIDDEN)

            # Verify the image if not yet verified
            if not image.verified:
                verified, message = image.verify_image()
            else:
                verified, message = True, "Image already verified"

            # Get download URL if verified
            download_url = None
            if verified and image.original_image:
                download_url = request.build_absolute_uri(image.original_image.url)

            return Response({
                "image_id": image.id,
                "verification_status": verified,
                "message": message,
                "metadata":image.metadata,
                "download_url": download_url
            })

        except UploadedImage.DoesNotExist:
            return Response({"error": "Image not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Error in image verification: {str(e)}")
            logger.error(error_trace)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Image download API
class ImageDownloadView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, image_id):
        try:
            image = UploadedImage.objects.get(id=image_id)

            # Check if user has permission to download this image
            if image.user != request.user and not request.user.is_staff:
                return Response({"error": "Not authorized to download this image"},
                                status=status.HTTP_403_FORBIDDEN)

            # Check if the image is verified
            if not image.verified:
                return Response({"error": "Image has not been verified. Please verify before downloading."},
                                status=status.HTTP_400_BAD_REQUEST)

            # Check if the original image exists
            if not image.original_image:
                # If the original image doesn't exist, try to verify it again
                verified, message = image.verify_image()
                if not verified or not image.original_image:
                    return Response({"error": "Failed to prepare image for download."},
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Get the file path
            file_path = image.original_image.path

            # Check if file exists
            if not os.path.exists(file_path):
                raise Http404("File not found")

            # Open the file for reading
            file = open(file_path, 'rb')

            # Get the filename
            filename = os.path.basename(file_path)

            # Return the file as a response
            response = FileResponse(file, content_type='image/jpeg')
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response

        except UploadedImage.DoesNotExist:
            return Response({"error": "Image not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Error in image download: {str(e)}")
            logger.error(error_trace)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@require_GET
def admin_image_download(request, image_id):
    """Special download view for admin panel that uses Django's authentication"""
    try:
        image = UploadedImage.objects.get(id=image_id)

        # Check if the image is verified
        if not image.verified:
            return HttpResponse("Image has not been verified. Please verify before downloading.",
                                status=400, content_type="text/plain")

        # Check if the original image exists
        if not image.original_image:
            return HttpResponse("Original image not found.",
                                status=404, content_type="text/plain")

        # Get the file path
        file_path = image.original_image.path

        # Check if file exists
        if not os.path.exists(file_path):
            raise Http404("File not found")

        # Open the file for reading
        file = open(file_path, 'rb')

        # Get the filename
        filename = os.path.basename(file_path)

        # Return the file as a response
        response = FileResponse(file, content_type='image/jpeg')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    except UploadedImage.DoesNotExist:
        raise Http404("Image not found")
    except Exception as e:
        logger.error(f"Error in admin image download: {str(e)}")
        return HttpResponse(f"Error: {str(e)}", status=500, content_type="text/plain")

class BulkImageDownloadView(APIView):
    """
    API endpoint to download all verified images for a user
    GET /download/all/ - Get all verified images as a JSON array
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Get all verified images for the user
            images = UploadedImage.objects.filter(
                user=request.user,
                verified=True,
                original_image__isnull=False
            ).order_by('-uploaded_at')

            if not images:
                return Response(
                    {"message": "No verified images found to download"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Get the user's public key
            user_public_key = request.user.get_public_key()
            if not user_public_key:
                return Response(
                    {"error": "User's public key not found. Please set up your public key first."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Prepare response data
            response_data = {
                "download_date": timezone.now().isoformat(),
                "user_id": request.user.id,
                "username": request.user.username,
                "total_images": len(images),
                "images": []
            }

            # Process each image
            for idx, image in enumerate(images):
                try:
                    # Read the original decrypted image
                    image_path = image.original_image.path
                    with open(image_path, 'rb') as img_file:
                        image_data = img_file.read()

                    # Generate new AES key for this image
                    aes_key = secrets.token_bytes(32)  # 256-bit key

                    # Create AESGCM object with the new AES key
                    aesgcm = AESGCM(aes_key)

                    # Generate a random IV (nonce)
                    iv = secrets.token_bytes(12)  # 96 bits as recommended for GCM

                    # Encrypt the image data
                    encrypted_data = aesgcm.encrypt(iv, image_data, None)

                    # Combine encrypted data and IV for storage
                    combined_data = encrypted_data + iv

                    # Encrypt the AES key with user's public key
                    encrypted_aes_key = user_public_key.encrypt(
                        aes_key,
                        padding.PKCS1v15()
                    )

                    # Compute hash of the original image data for verification
                    image_hash = hashlib.sha256(image_data).digest()
                    base64_hash = base64.b64encode(image_hash).decode('utf-8')

                    # Base64 encode the binary data for JSON
                    base64_encrypted_data = base64.b64encode(combined_data).decode('utf-8')
                    base64_encrypted_key = base64.b64encode(encrypted_aes_key).decode('utf-8')

                    # Create image object in the frontend format
                    image_obj = {
                        "id": f"image{image.id}",
                        "imageUrl": request.build_absolute_uri(
                            image.original_image.url) if image.original_image else None,
                        "encryptedData": base64_encrypted_data,
                        "encryptedAESKey": base64_encrypted_key,
                        "isEncrypted": True,
                        "hash": base64_hash,
                        "uploadDate": image.uploaded_at.isoformat(),
                        "metadata": image.metadata
                    }

                    response_data["images"].append(image_obj)

                except Exception as e:
                    logger.error(f"Error processing image {image.id}: {str(e)}")
                    # Add error to metadata instead of failing entire request
                    response_data["images"].append({
                        "id": f"image{image.id}",
                        "error": str(e),
                        "isEncrypted": False
                    })

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in bulk download: {str(e)}")
            return Response(
                {"error": f"Error processing request: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )