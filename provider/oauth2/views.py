import datetime
import json

from datetime import timedelta
from django.urls import reverse
from django.http import HttpResponseRedirect, QueryDict, HttpResponseForbidden, HttpResponse
from django.utils import timezone
from django.contrib.auth import logout

from .. import constants
from ..views import Capture, Authorize, Redirect, get_post_data
from ..views import AccessToken as AccessTokenView, OAuthError, OAuthView, Mixin
from ..utils import now
from .forms import AuthorizationRequestForm, AuthorizationForm
from .forms import PasswordGrantForm, RefreshTokenGrantForm
from .forms import AuthorizationCodeGrantForm
from .models import Client, RefreshToken, AccessToken
from .backends import BasicClientBackend, RequestParamsClientBackend, PublicPasswordBackend


class Capture(Capture):
    """
    Implementation of :class:`provider.views.Capture`.
    """
    def get_redirect_url(self, request):
        return reverse('oauth2:authorize')

    def handle(self, request, data):
        self.cache_data(request, data)

        if constants.ENFORCE_SECURE and not request.is_secure():
            return self.render_to_response({'error': 'access_denied',
                'error_description': _("A secure connection is required."),
                'next': None},
                status=400)
        if hasattr(request, 'auth'):
            request.method = 'GET'
            return Authorize.as_view()(request)
        return HttpResponseRedirect(self.get_redirect_url(request))

class Authorize(Authorize):
    """
    Implementation of :class:`provider.views.Authorize`.
    """
    def get_request_form(self, client, data):
        return AuthorizationRequestForm(data, client=client)

    def get_authorization_form(self, request, client, data, client_data):
        return AuthorizationForm(data)

    def get_client(self, client_id):
        try:
            return Client.objects.get(client_id=client_id)
        except Client.DoesNotExist:
            return None

    def get_redirect_url(self, request):
        return reverse('oauth2:redirect')

    def save_authorization(self, request, client, form, client_data):

        grant = form.save(commit=False)

        if grant is None:
            return None

        grant.user = request.user
        grant.client = client
        grant.redirect_uri = client_data.get('redirect_uri', '')
        grant.save()
        return grant.code


class Redirect(Redirect):
    """
    Implementation of :class:`provider.views.Redirect`
    """
    pass


class AccessTokenView(AccessTokenView):
    """
    Implementation of :class:`provider.views.AccessToken`.

    .. note:: This implementation does provide all default grant types defined
        in :attr:`provider.views.AccessToken.grant_types`. If you
        wish to disable any, you can override the :meth:`get_handler` method
        *or* the :attr:`grant_types` list.
    """
    authentication = (
        BasicClientBackend,
        RequestParamsClientBackend,
        PublicPasswordBackend,
    )

    def get_authorization_code_grant(self, request, data, client):
        form = AuthorizationCodeGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data.get('grant')

    def get_refresh_token_grant(self, request, data, client):
        form = RefreshTokenGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data.get('refresh_token')

    def get_password_grant(self, request, data, client):
        form = PasswordGrantForm(data, client=client)
        if not form.is_valid():
            raise OAuthError(form.errors)
        return form.cleaned_data

    def get_access_token(self, request, user, scope, client):
        try:
            # Attempt to fetch an existing access token.
            at = AccessToken.objects.get(user=user, client=client,
                                         scope=scope, expires__gt=now())
        except AccessToken.DoesNotExist:
            # None found... make a new one!
            at = self.create_access_token(request, user, scope, client)
            self.create_refresh_token(request, user, scope, at, client)
        return at

    def create_access_token(self, request, user, scope, client):
        parameters = {}
        if client.is_public:
            parameters = {'expires': timezone.now() + datetime.timedelta(days=7)}
        return AccessToken.objects.create(
            user=user,
            client=client,
            scope=scope,
            **parameters
        )

    def create_refresh_token(self, request, user, scope, access_token, client):
        return RefreshToken.objects.create(
            user=user,
            access_token=access_token,
            client=client
        )

    def invalidate_grant(self, grant):
        if constants.DELETE_EXPIRED:
            grant.delete()
        else:
            grant.expires = now() - timedelta(days=1)
            grant.save()

    def invalidate_refresh_token(self, rt):
        if constants.DELETE_EXPIRED:
            rt.delete()
        else:
            rt.expired = True
            rt.save()

    def invalidate_access_token(self, at):
        if constants.DELETE_EXPIRED:
            at.delete()
        else:
            at.expires = now() - timedelta(days=1)
            at.save()


class LogoutView(OAuthView, Mixin):
    authentication = (
        BasicClientBackend,
        RequestParamsClientBackend,
        PublicPasswordBackend,
    )
    def get(self, request, *args, **kwargs):
        return HttpResponse(json.dumps({'error': 'Method not allowed.'}), content_type='application/json',
                status=405, **kwargs)

    def post(self, request):
        """
        As per :rfc:`3.2` the token endpoint *only* supports POST requests.
        """
        get_post_data(request)

        if constants.ENFORCE_SECURE and not request.is_secure():
            return self.error_response({
                'error': 'invalid_request',
                'error_description': _("A secure connection is required.")})

        if hasattr(request, 'auth') and request.auth:
            request.auth.expires = timezone.now()
            request.auth.save()
            request.auth.refresh_token.expired = True
            request.auth.refresh_token.save()
        else:
            logout(request.user)
        return self.success_response({'status': 'SUCCESS', 'message': 'Successfully logged out.'})

    def success_response(self, success_message, content_type='application/json', status=200,
            **kwargs):
        """
        Return an error response to the client with default status code of
        *400* stating the error as outlined in :rfc:`5.2`.
        """
        return HttpResponse(json.dumps(success_message), content_type=content_type,
                status=status, **kwargs)
