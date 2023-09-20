from provider.compat.urls import *
from django.contrib import admin

admin.autodiscover()

urlpatterns = ['',
    url(r'^admin/', admin.site.urls),
    url(r'^oauth2/', include(('provider.oauth2.urls', 'provider.oauth2'), namespace='oauth2')),
]
