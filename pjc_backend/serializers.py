from rest_framework import serializers
from .models import UploadedImage, CustomUser


class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    public_key = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'email', 'phone_number', 'id_card', 'password', 'public_key')

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        return user


class PublicKeySerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='username', read_only=True)

    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'public_key')
        read_only_fields = ('id', 'username')


class UploadedImageSerializer(serializers.ModelSerializer):
    hash_value = serializers.CharField(read_only=True)
    verification_status = serializers.SerializerMethodField()
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = UploadedImage
        fields = ('id', 'original_image', 'hash_value', 'metadata', 'verification_status', 'uploaded_at', 'image_url', 'caption')
        read_only_fields = ('hash_value', 'metadata', 'verification_status', 'image_url')

    def get_verification_status(self, obj):
        return obj.verified

    def get_image_url(self, obj):
        if obj.verified and obj.original_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.original_image.url)
        return None

    # def create(self, validated_data):
    #     user = validated_data.pop('user')
    #     image_file = validated_data.pop('image')
    #     encrypted_data = validated_data.pop('encrypted_data', None)
    #     provided_hash = validated_data.pop('provided_hash', None)
    #
    #     # Use the upload_image class method to handle the encryption and hashing
    #     upload, computed_hash = UploadedImage.upload_image(
    #         user,
    #         image_file,
    #         encrypted_data=encrypted_data,
    #         provided_hash=provided_hash
    #     )
    #
    #     return upload