from django.conf.urls import url
from django.conf.urls import include

from rest_framework.routers import DefaultRouter

from . import views
from .html_views import password_reset_from_key

router = DefaultRouter()
router.register('hello-viewset', views.HelloViewSet, base_name='hello-viewset')
router.register('profile', views.UserProfileViewSet)
router.register('login', views.LoginViewSet, base_name='login')
router.register('feed', views.UserProfileFeedViewSet)

urlpatterns = [
    url(r'^hello-view/', views.HelloApiView.as_view()),
    url(r'', include(router.urls)),
    url(r'^account/password/$',
        views.account_password_reset, name='account_password_reset'),
    # url(r'^account/password/reset/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$', views.account_password_reset_key,
    #     name='account_password_reset_key'),

    url(r"^account/password/reset/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$",
                password_reset_from_key,
                name="account_password_reset_key"),
]
