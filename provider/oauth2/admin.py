from django.contrib import admin
from .models import AccessToken, Grant, Client, RefreshToken

from django.contrib.contenttypes.models import ContentType
from django.utils.safestring import mark_safe
from django.urls import reverse


def refresh_token_url(obj, *args, **kwargs):
    if not obj.refresh_token:
        return None

    ct = ContentType.objects.get_for_model(RefreshToken)
    try:
        url = reverse(
            "admin:%s_%s_change" % (ct.app_label, ct.model),
            args=[obj.refresh_token.id],
        )
    except Exception as e:
        return None

    return mark_safe('<a href="%s">%s</a>' % (url, obj.refresh_token.token))


class AccessTokenAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "client",
        "token",
        "expires",
        "scope",
        "created",
        "modified",
        refresh_token_url,
    )
    raw_id_fields = ("user",)
    readonly_fields = ("created", "modified")
    search_fields = ["user__username"]
    list_filter = ["client"]


class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "token",
        "access_token",
        "client",
        "expired",
        "created",
        "modified",
    )
    raw_id_fields = ("user", "access_token", "client")
    readonly_fields = ("created", "modified")


class GrantAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "client",
        "code",
        "expires",
    )
    raw_id_fields = ("user",)


class ClientAdmin(admin.ModelAdmin):
    list_display = ("name", "url", "user", "redirect_uri", "client_id", "client_type")
    raw_id_fields = ("user",)


admin.site.register(AccessToken, AccessTokenAdmin)
admin.site.register(Grant, GrantAdmin)
admin.site.register(Client, ClientAdmin)
admin.site.register(RefreshToken, RefreshTokenAdmin)
