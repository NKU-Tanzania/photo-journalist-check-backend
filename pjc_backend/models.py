from django.contrib.auth.models import AbstractUser, Group, Permission
from .managers import CustomUserManager
from django.db import models
from django.contrib.auth import get_user_model
from cryptography.hazmat.primitives import hashes, serialization
import base64
import logging
import hashlib
import datetime
import requests

# Set up logging
logger = logging.getLogger(__name__)

# Custom user model
class CustomUser(AbstractUser):
    phone_number = models.CharField(max_length=15, unique=True)
    id_card = models.CharField(max_length=50, unique=True)
    # User public key (received from client)
    public_key = models.TextField(blank=True, null=True)
    # Server-side private key (generated for this user)
    server_private_key = models.TextField(blank=True, null=True)
    # Server-side public key (paired with server_private_key)
    server_public_key = models.TextField(blank=True, null=True)

    groups = models.ManyToManyField(Group, related_name='customuser_groups')
    user_permissions = models.ManyToManyField(Permission, related_name='customuser_permissions')

    objects = CustomUserManager()

    def __str__(self):
        return self.username

    def get_public_key(self):
        """Deserialize and return the public key object"""
        if not self.public_key:
            return None

        try:
            # The frontend sends base64-encoded DER format
            from cryptography.hazmat.backends import default_backend

            # Decode the base64 data to get the DER-encoded key
            der_data = base64.b64decode(self.public_key)

            # Load the DER-encoded key
            return serialization.load_der_public_key(
                der_data,
                backend=default_backend()
            )

        except Exception as e:
            logger.error(f"Error loading public key for user {self.username}: {str(e)}")
            # Log some diagnostic info about the key
            if self.public_key:
                logger.debug(f"Key length: {len(self.public_key)}, First 20 chars: {self.public_key[:20]}")
            return None

User = get_user_model()

# Image upload model
class UploadedImage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    original_image = models.ImageField(upload_to='original/', blank=True, null=True)
    # This contains the encrypted data from the client
    encrypted_image = models.BinaryField()
    hash_value = models.CharField(max_length=255)  # Increased length to accommodate Base64
    calculated_hash_value = models.CharField(max_length=255)  # Increased length to accommodate Base64
    metadata = models.JSONField(default=dict)
    verified = models.BooleanField(default=False)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    aes_key = models.BinaryField()

    def compute_hash(self, image_data):
        """Compute SHA-256 hash of image data"""
        return hashlib.sha256(image_data).hexdigest()
    
    def extract_metadata(self, img=None):
        """Extract comprehensive metadata from image or create default metadata"""
        metadata = {
            "user_id": self.user.id,
            "username": self.user.username,
            "timestamp": datetime.datetime.now().isoformat(),
            "verification_time": datetime.datetime.now().isoformat(),
        }

        # If we have an actual image, extract more metadata
        if img:
            # Basic image properties
            metadata.update({
                "image_format": img.format,
                "image_size": f"{img.width}x{img.height} pixels",
                "image_mode": img.mode,
                "image_width": img.width,
                "image_height": img.height,
                "aspect_ratio": round(img.width / img.height, 2) if img.height else None,
                "color_mode": img.mode,
            })

            # Extract EXIF data if available
            if hasattr(img, '_getexif') and img._getexif():
                exif = img._getexif()
                if exif:
                    # Common EXIF tags and their friendly names
                    exif_tags = {
                        0x8769: 'ExifOffset',
                        0x0110: 'Model',
                        0x010F: 'Make',
                        0x9003: 'DateTimeOriginal',
                        0x8827: 'ISOSpeedRatings',
                        0x920A: 'FocalLength',
                        0x829A: 'ExposureTime',
                        0x829D: 'FNumber',
                        0xA002: 'ImageWidth',
                        0xA003: 'ImageHeight',
                        0x0128: 'ResolutionUnit',
                        0x0131: 'Software',
                        0x0132: 'DateTime',
                        0x8822: 'ExposureProgram',
                        0xA001: 'ColorSpace',
                        0xA402: 'ExposureMode',
                        0xA403: 'WhiteBalance',
                        0xA406: 'SceneCaptureType',
                        0x0112: 'Orientation',
                        0xA004: 'RelatedSoundFile',
                        0x9286: 'UserComment',
                        0x9290: 'SubsecTime',
                    }

                    for tag, tag_name in exif_tags.items():
                        if tag in exif:
                            metadata[f"exif_{tag_name}"] = str(exif[tag])

            # Try to get some additional info if available
            if hasattr(img, 'info'):
                for key, value in img.info.items():
                    # Only include serializable metadata
                    try:
                        json.dumps({key: value})
                        metadata[f"img_info_{key}"] = value
                    except (TypeError, OverflowError):
                        pass

            # Try to detect image content type for additional context
            try:
                # Calculate some general image statistics
                img_stats = img.convert('RGB')
                r, g, b = 0, 0, 0
                pixels = img_stats.width * img_stats.height

                # Sample pixels to get average color
                sample_size = min(100, pixels)
                if sample_size > 0:
                    step_x = max(1, img_stats.width // 10)
                    step_y = max(1, img_stats.height // 10)

                    sampled_pixels = 0
                    for x in range(0, img_stats.width, step_x):
                        for y in range(0, img_stats.height, step_y):
                            if sampled_pixels < sample_size:
                                try:
                                    pixel = img_stats.getpixel((x, y))
                                    if len(pixel) >= 3:
                                        r += pixel[0]
                                        g += pixel[1]
                                        b += pixel[2]
                                        sampled_pixels += 1
                                except:
                                    pass

                    if sampled_pixels > 0:
                        metadata["avg_color_r"] = r / sampled_pixels
                        metadata["avg_color_g"] = g / sampled_pixels
                        metadata["avg_color_b"] = b / sampled_pixels

                        # Brightness approximation
                        brightness = (0.299 * r + 0.587 * g + 0.114 * b) / sampled_pixels / 255
                        metadata["brightness"] = round(brightness, 2)

                        # Simple classification based on brightness
                        if brightness < 0.3:
                            metadata["brightness_category"] = "dark"
                        elif brightness > 0.7:
                            metadata["brightness_category"] = "bright"
                        else:
                            metadata["brightness_category"] = "medium"

            except Exception as e:
                metadata["image_analysis_error"] = str(e)

        return metadata

    @classmethod
    def upload_image(cls, user, image_file, aes_key, provided_hash=None, metadata=None):
        """
        Process image upload:
        1. Store the encrypted image data from client
        2. Store the provided hash value
        3. Store the provided metadata from client
        4. Create minimal metadata if none provided
        """
        # Create the model instance
        upload = cls(user=user)

        try:
            # Store the encrypted image data as is
            image_file.seek(0)  # Reset file pointer
            upload.encrypted_image = image_file.read()

            # Add a field to store the encrypted key
            upload.aes_key = aes_key

            # Store the provided hash as is (it may be Base64 encoded)
            if provided_hash:
                upload.hash_value = provided_hash
            else:
                # This is a fallback and might not be useful for verification
                upload.hash_value = upload.compute_hash(upload.encrypted_image)

            # Create basic metadata
            base_metadata = {
                "user_id": user.id,
                "upload_timestamp": datetime.datetime.now().isoformat(),
                "original_filename": getattr(image_file, 'name', 'unknown'),
                "encrypted_size": len(upload.encrypted_image),
                "status": "encrypted"
            }

            # Merge with client-provided metadata if it exists
            if metadata and isinstance(metadata, dict):
                # Create a new dictionary with base metadata and update with client metadata
                combined_metadata = base_metadata.copy()
                combined_metadata.update(metadata)

                # Add processing indicators
                combined_metadata["client_metadata_received"] = True

                # Process specific metadata fields for validation/enhancement
                if "location" in metadata and isinstance(metadata["location"], dict):
                    loc = metadata["location"]
                    if "latitude" in loc and "longitude" in loc:
                        # Add reverse geocoding data
                        try:
                            geocode_result = reverse_geocode(loc["latitude"], loc["longitude"])
                            combined_metadata["location"]["address"] = geocode_result
                        except Exception as e:
                            combined_metadata["location"]["geocode_error"] = str(e)

                # Process device information
                if "device_manufacturer" in metadata and "device_model" in metadata:
                    combined_metadata["device_identified"] = True

                # Process OS information
                if "os_name" in metadata and "os_version" in metadata:
                    combined_metadata["os_identified"] = True

                upload.metadata = combined_metadata
            else:
                # Use just the base metadata if none provided
                upload.metadata = base_metadata

            # Save the upload - the original_image field will be populated during verification
            upload.save()

            return upload, upload.hash_value

        except Exception as e:
            logger.error(f"Error in upload_image: {str(e)}")
            raise

    def reverse_geocode(latitude, longitude):
        """Convert coordinates to human-readable address"""
        try:
            # Using Nominatim (OpenStreetMap) - free but has usage limits
            url = f"https://nominatim.openstreetmap.org/reverse?lat={latitude}&lon={longitude}&format=json"
            headers = {'User-Agent': 'YourApp/1.0'}  # Required by Nominatim

            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                return {
                    'address': data.get('display_name', 'Unknown location'),
                    'city': data.get('address', {}).get('city', ''),
                    'state': data.get('address', {}).get('state', ''),
                    'country': data.get('address', {}).get('country', '')
                }
        except Exception as e:
            print(f"Geocoding error: {e}")

        return {'address': 'Location unavailable'}