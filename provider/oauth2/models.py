"""
Default model implementations. Custom database or OAuth backends need to
implement these models with fields and and methods to be compatible with the
views in :attr:`provider.views`.
"""

from django.db import models
from django.conf import settings
from .. import constants
from ..constants import CLIENT_TYPES
from ..utils import now, short_token, long_token, get_code_expiry
from ..utils import get_token_expiry, serialize_instance, deserialize_instance
from .managers import AccessTokenManager

try:
    from django.utils import timezone
except ImportError:
    timezone = None

AUTH_USER_MODEL = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')


class Client(models.Model):
    """
    Default client implementation.

    Expected fields:

    * :attr:`user`
    * :attr:`name`
    * :attr:`url`
    * :attr:`redirect_url`
    * :attr:`client_id`
    * :attr:`client_secret`
    * :attr:`client_type`

    Clients are outlined in the :rfc:`2` and its subsections.
    """

    class Meta:
        db_table = 'oauth2_client'

    user = models.ForeignKey(AUTH_USER_MODEL, related_name='oauth2_client',
        blank=True, null=True, on_delete=models.CASCADE)
    name = models.CharField(max_length=255, blank=True)
    url = models.URLField(help_text="Your application's URL.")
    redirect_uri = models.URLField(help_text="Your application's callback URL")
    client_id = models.CharField(max_length=255, default=short_token)
    client_secret = models.CharField(max_length=255, default=long_token)
    client_type = models.IntegerField(choices=CLIENT_TYPES)

    def __str__(self):
        return self.redirect_uri

    def get_default_token_expiry(self):
        public = (self.client_type == 1)
        return get_token_expiry(public)

    def serialize(self):
        return dict(user=serialize_instance(self.user) if self.user else "",
                    name=self.name,
                    url=self.url,
                    redirect_uri=self.redirect_uri,
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    client_type=self.client_type)

    @property
    def sandbox_client(self):
        return self.user and self.user.username == 'oauth2-sandbox-user'

    @property
    def is_public(self):
        return self.user != None

    @classmethod
    def deserialize(cls, data):
        if not data:
            return None

        kwargs = {}

        # extract values that we care about
        for field in cls._meta.fields:
            name = field.name
            val = data.get(field.name, None)

            # handle relations
            if val and field.remote_field:
                val = deserialize_instance(field.remote_field.model, val)

            kwargs[name] = val

        return cls(**kwargs)


class Grant(models.Model):
    """
    Default grant implementation. A grant is a code that can be swapped for an
    access token. Grants have a limited lifetime as defined by
    :attr:`provider.constants.EXPIRE_CODE_DELTA` and outlined in
    :rfc:`4.1.2`

    Expected fields:

    * :attr:`user`
    * :attr:`client` - :class:`Client`
    * :attr:`code`
    * :attr:`expires` - :attr:`datetime.datetime`
    * :attr:`redirect_uri`
    * :attr:`scope`
    """
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    code = models.CharField(max_length=255, default=long_token)
    expires = models.DateTimeField(default=get_code_expiry)
    redirect_uri = models.CharField(max_length=255, blank=True)
    scope = models.IntegerField(default=0)

    class Meta:
        db_table = 'oauth2_grant'

    def __str__(self):
        return self.code


class AccessToken(models.Model):
    """
    Default access token implementation. An access token is a time limited
    token to access a user's resources.

    Access tokens are outlined :rfc:`5`.

    Expected fields:

    * :attr:`user`
    * :attr:`token`
    * :attr:`client` - :class:`Client`
    * :attr:`expires` - :attr:`datetime.datetime`
    * :attr:`scope`

    Expected methods:

    * :meth:`get_expire_delta` - returns an integer representing seconds to
        expiry
    """
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE, help_text='Add user to restrict client to public apis.')
    token = models.CharField(max_length=255, default=long_token, db_index=True)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    expires = models.DateTimeField()
    scope = models.IntegerField(default=constants.SCOPES[0][0],
            choices=constants.SCOPES)

    logged_out = models.DateTimeField(null=True, blank=True)
    device_id = models.CharField(null=True, blank=True, max_length=511)

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    objects = AccessTokenManager()

    class Meta:
        db_table = 'oauth2_accesstoken'

    def __str__(self):
        return self.token

    def save(self, *args, **kwargs):
        if not self.expires:
            self.expires = self.client.get_default_token_expiry()
        super(AccessToken, self).save(*args, **kwargs)

    def get_expire_delta(self, reference=None):
        """
        Return the number of seconds until this token expires.
        """
        if reference is None:
            reference = now()
        expiration = self.expires

        if timezone:
            if timezone.is_aware(reference) and timezone.is_naive(expiration):
                # MySQL doesn't support timezone for datetime fields
                # so we assume that the date was stored in the UTC timezone
                expiration = timezone.make_aware(expiration, timezone.utc)
            elif timezone.is_naive(reference) and timezone.is_aware(expiration):
                reference = timezone.make_aware(reference, timezone.utc)

        timedelta = expiration - reference
        return timedelta.days*86400 + timedelta.seconds


class RefreshToken(models.Model):
    """
    Default refresh token implementation. A refresh token can be swapped for a
    new access token when said token expires.

    Expected fields:

    * :attr:`user`
    * :attr:`token`
    * :attr:`access_token` - :class:`AccessToken`
    * :attr:`client` - :class:`Client`
    * :attr:`expired` - ``boolean``
    """
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, default=long_token)
    access_token = models.OneToOneField(AccessToken, related_name='refresh_token', on_delete=models.CASCADE)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    expired = models.BooleanField(default=False)

    class Meta:
        db_table = 'oauth2_refreshtoken'

    def __str__(self):
        return self.token
