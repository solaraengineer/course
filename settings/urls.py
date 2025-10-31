from django.contrib import admin
from django.urls import path, re_path
from logic.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('register', register, name='register'),
    path('login', login, name='login'),
    path('dash', dash, name='dash'),
    path('Update', Update, name='Update'),
    path('Sub', subscriptions, name='sub'),
    path('success', success, name='success'),
    path('create-checkout-session/', create_checkout_session, name='create-checkout-session'),
    path('webhook/stripe/', stripe_webhook, name='stripe-webhook'),
    path('Fsettings', Fsettings, name='settings'),
    path('more', more, name='more'),
    path('preview', preview, name='preview'),
    path('beginner', begineer, name='beginner'),
    path('inter', inter, name='inter'),
    path('adv', adv, name='adv'),
    path('sen', sen, name='sen'),
    path('mark', mark, name='mark'),
    path('terms', terms, name='terms'),

    path('<str:tier>lesson<int:number>/', dynamic_lesson_view, name='lesson'),
    path('<str:tier>pro<int:number>/', dynamic_project_view, name='project'),
    path('<str:tier>sum<int:number>/', dynamic_summary_view, name='summary'),
    path('<tier>/<type>/<int:number>', dynamic_content, name='dynamic-content'),

]