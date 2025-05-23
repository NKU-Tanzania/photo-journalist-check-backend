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


            # Use the model's class method to handle the upload
            upload, computed_hash = UploadedImage.upload_image(
                user,
                image_file,
                aes_key,
                provided_hash=provided_hash,
                metadata=metadata
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
