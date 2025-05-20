import io
from django.contrib.auth.models import AbstractUser, Group, Permission
from .managers import CustomUserManager
from django.db import models
from django.contrib.auth import get_user_model
from cryptography.hazmat.primitives import serialization
import base64
import logging
import hashlib
import datetime
import requests
from PIL import Image
from cryptography.hazmat.primitives.asymmetric import padding
from django.core.files.base import ContentFile
import json

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
    
    def get_server_private_key(self):
        """Get the server's private key for this image's user"""
        if not self.user.server_private_key:
            return None

        try:
            from cryptography.hazmat.backends import default_backend
            pem_data = self.user.server_private_key.encode('utf-8')
            return serialization.load_pem_private_key(
                pem_data,
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            logger.error(f"Error loading server private key: {str(e)}")
            return None

    def verify_image(self):
        # Get server's private key
        private_key = self.get_server_private_key()
        if not private_key:
            logger.error(f"Server private key not found for user {self.user.username}")
            return False, "Server private key not found"

        try:
            logger.info(f"Attempting to verify image for user {self.user.username}")

            try:
                # Ensure aes_key is accessed as bytes (fix for BinaryField issue)
                aes_key_bytes = bytes(self.aes_key)

                # Decrypt the AES key using the server's private key
                decrypted_aes_key = private_key.decrypt(
                    aes_key_bytes,
                    padding.PKCS1v15()
                )

                # Convert encrypted_image to bytes if needed
                encrypted_image_bytes = bytes(self.encrypted_image)

                # For GCM, IV is typically 12 bytes (96 bits)
                # Extract the IV from the end of the data
                iv_length = 12  # Standard for GCM

                if len(encrypted_image_bytes) <= iv_length:
                    logger.error("Encrypted data too short to contain IV")
                    return False, "Encrypted data too short"

                encrypted_data = encrypted_image_bytes[:-iv_length]
                iv = encrypted_image_bytes[-iv_length:]

                logger.debug(f"Encrypted data length: {len(encrypted_data)}, IV length: {len(iv)}")

                # Use AESGCM for simpler handling
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                try:
                    # Create AESGCM object with the decrypted key
                    aesgcm = AESGCM(decrypted_aes_key)

                    # Decrypt the data - for GCM the tag is part of the ciphertext
                    # in the cryptography library's AESGCM implementation
                    decrypted_data = aesgcm.decrypt(iv, encrypted_data, None)

                    logger.debug(f"Successfully decrypted data, size: {len(decrypted_data)} bytes")

                    # Calculate hash and verify
                    computed_hash = hashlib.sha256(decrypted_data).hexdigest()
                    logger.debug(f"Computed hash: {computed_hash[:20]}...")
                    logger.debug(f"Stored hash: {self.hash_value[:20]}...")

                    hash_verified = False
                    if computed_hash == self.hash_value:
                        logger.info("Hash verification successful!")
                        hash_verified = True
                    else:
                        # Try base64 format
                        base64_hash = base64.b64encode(hashlib.sha256(decrypted_data).digest()).decode('utf-8')
                        if base64_hash == self.hash_value:
                            logger.info(
                                f"Sent Hash: {self.hash_value[:20]}... = Calculated Hash: {base64_hash[:20]}...")
                            logger.info("Hash verification successful!!")
                            hash_verified = True

                    if hash_verified:
                        self.calculated_hash_value = computed_hash if computed_hash == self.hash_value else base64_hash
                        # Save the decrypted image
                        try:
                            # Create a BytesIO object from the decrypted data
                            image_data = io.BytesIO(decrypted_data)

                            # Try to open as an image to extract metadata
                            try:
                                img = Image.open(image_data)
                                # Extract image metadata but preserve client metadata
                                img_metadata = self.extract_metadata(img)

                                # Keep original client metadata
                                client_metadata = self.metadata.copy()

                                # Update with image metadata but don't overwrite client metadata
                                # for key, value in img_metadata.items():
                                #     if key not in client_metadata:
                                #         client_metadata[key] = value

                                # Instead of above, separate image-specific data
                                client_metadata["extracted_image_data"] = img_metadata

                                # Reset the pointer to the beginning of the file
                                image_data.seek(0)

                                # Update the metadata
                                self.metadata = client_metadata

                            except Exception as e:
                                logger.warning(f"Failed to extract metadata from image: {str(e)}")
                                # Keep existing metadata but add the error
                                self.metadata["extraction_error"] = str(e)

                            # Save the decrypted image to the original_image field
                            timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
                            filename = f"decrypted_{self.user.username}_{timestamp}.jpg"
                            self.original_image.save(
                                filename,
                                ContentFile(decrypted_data),
                                save=False
                            )

                            # Add additional verification metadata
                            self.metadata.update({
                                "verification_status": "success",
                                "verification_time": datetime.datetime.now().isoformat(),
                                "verification_filename": filename,
                                "file_size_bytes": len(decrypted_data),
                                "file_size_readable": f"{len(decrypted_data) / 1024:.2f} KB",
                            })

                            # Mark as verified
                            self.verified = True
                            self.save()
                            return True, "Verification completed successfully"
                        except Exception as save_error:
                            logger.error(f"Failed to save decrypted image: {str(save_error)}")
                            return False, f"Failed to save decrypted image: {str(save_error)}"
                    else:
                        logger.error(f"Hash mismatch")
                        return False, "Hash verification failed: hashes don't match"

                except Exception as e:
                    logger.error(f"AESGCM decryption failed: {str(e)}")

                    # If that doesn't work, the IV and encrypted data might be structured differently
                    # Let's try one more approach based on how the Android client might be sending data

                    # In some Android implementations, the GCM tag (16 bytes) is appended after the encrypted data
                    # and before the IV (12 bytes)

                    if len(encrypted_image_bytes) < 28:  # Need at least 16 (tag) + 12 (IV)
                        return False, "Encrypted data too short for alternative method"

                    # Try extracting IV from end, and tag from before IV
                    iv = encrypted_image_bytes[-12:]
                    tag = encrypted_image_bytes[-28:-12]  # 16 bytes before IV
                    actual_encrypted_data = encrypted_image_bytes[:-28]

                    logger.debug(
                        f"Alt method - Data: {len(actual_encrypted_data)} bytes, Tag: {len(tag)} bytes, IV: {len(iv)} bytes")

                    # Try with Cipher/modes.GCM
                    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

                    try:
                        # Create cipher with explicit tag handling
                        gcm = modes.GCM(iv, tag)
                        cipher = Cipher(algorithms.AES(decrypted_aes_key), gcm)
                        decryptor = cipher.decryptor()

                        decrypted_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()

                        # Verify hash
                        computed_hash = hashlib.sha256(decrypted_data).hexdigest()

                        hash_verified = False
                        if computed_hash == self.hash_value:
                            hash_verified = True
                        else:
                            # Try base64 format
                            base64_hash = base64.b64encode(hashlib.sha256(decrypted_data).digest()).decode('utf-8')
                            if base64_hash == self.hash_value:
                                hash_verified = True

                        if hash_verified:
                            self.calculated_hash_value = computed_hash if computed_hash == self.hash_value else base64_hash
                            # Save the decrypted image
                            try:
                                # Create a BytesIO object from the decrypted data
                                image_data = io.BytesIO(decrypted_data)

                                # Try to open as an image to extract metadata
                                try:
                                    img = Image.open(image_data)
                                    # Extract image metadata but preserve client metadata
                                    img_metadata = self.extract_metadata(img)

                                    # Keep original client metadata
                                    client_metadata = self.metadata.copy()

                                    # Separate image-specific data
                                    client_metadata["extracted_image_data"] = img_metadata

                                    # Reset the pointer to the beginning of the file
                                    image_data.seek(0)

                                    # Update the metadata
                                    self.metadata = client_metadata
                                except Exception as e:
                                    logger.warning(f"Failed to extract metadata from image: {str(e)}")
                                    # Keep existing metadata but add the error
                                    self.metadata["extraction_error"] = str(e)

                                # Save the decrypted image to the original_image field
                                timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
                                filename = f"decrypted_{self.user.username}_{timestamp}.jpg"
                                self.original_image.save(
                                    filename,
                                    ContentFile(decrypted_data),
                                    save=False
                                )

                                # Add additional verification metadata
                                self.metadata.update({
                                    "verification_status": "success (alt method)",
                                    "verification_time": datetime.datetime.now().isoformat(),
                                    "verification_filename": filename,
                                    "file_size_bytes": len(decrypted_data),
                                    "file_size_readable": f"{len(decrypted_data) / 1024:.2f} KB",
                                })

                                self.verified = True
                                self.save()
                                return True, "Verification completed successfully (alt method)"
                            except Exception as save_error:
                                logger.error(f"Failed to save decrypted image: {str(save_error)}")
                                return False, f"Failed to save decrypted image: {str(save_error)}"
                        else:
                            return False, "Hash verification failed: hashes don't match (alt method)"

                    except Exception as alt_e:
                        logger.error(f"Alternative decryption method failed: {str(alt_e)}")
                        return False, f"All decryption methods failed"

            except Exception as e:
                logger.error(f"Decryption failed: {str(e)}")
                return False, f"Decryption failed: {str(e)}"

        except Exception as e:
            logger.error(f"Verification error: {str(e)}")
            return False, f"Verification error: {str(e)}"

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