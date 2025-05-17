from django.db import models

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
