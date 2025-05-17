from django.contrib.auth.models import BaseUserManager

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, phone_number=None, id_card=None, **extra_fields):
        """Create and return a regular user with an email, phone number, and ID card."""
        if not email:
            raise ValueError("The Email field must be set")
        if not phone_number:
            raise ValueError("The Phone Number field must be set")
        if not id_card:
            raise ValueError("The ID Card field must be set")

        email = self.normalize_email(email)
        user = self.model(
            username=username,
            email=email,
            phone_number=phone_number,
            id_card=id_card,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        """Create and return a superuser."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        #generate default values
        if 'phone_number' not in extra_fields:
            extra_fields['phone_number'] = f"admin_{username}" #default value
        if 'id_card' not in extra_fields:
            extra_fields['id_card'] = f"admin_{username}" #default value


        return self.create_user(
            username=username,
            email=email,
            password=password,
            **extra_fields
        )