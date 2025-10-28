import stripe
from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login
from django.contrib import messages
from django.conf import settings
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
import requests

from logic.models import User
from logic.forms import RegistrationForm, LoginForm, UpdateForm
from json_response import JsonResponse  # your custom JsonResponse helper

# Stripe config
stripe.api_key = settings.STRIPE_SECRET_KEY


@ratelimit(key='ip', rate='5/m', block=True)
def login(request):
    form = LoginForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        cd = form.cleaned_data
        user = User.objects.filter(email=cd["email"]).first()

        if user and user.check_password(cd["password"]):
            auth_login(request, user)
            return redirect('dash')
        messages.error(request, "Invalid credentials", extra_tags="login")

    return render(request, "index.html", {
        "login_form": form,
        "reg_form": RegistrationForm(),
    })


@ratelimit(key='ip', rate='5/m', block=True)
def register(request):
    form = RegistrationForm(request.POST or None)

    if request.method == "POST":
        if form.is_valid():
            cd = form.cleaned_data
            username, email, password = cd["username"], cd["email"], cd["password"]

            # reCAPTCHA verification
            recaptcha_token = request.POST.get("g-recaptcha-response")
            verify_url = "https://www.google.com/recaptcha/api/siteverify"
            payload = {"secret": settings.RECAPTCHA_SECRET_KEY, "response": recaptcha_token}

            try:
                response = requests.post(verify_url, data=payload, timeout=5)
                result = response.json()
            except Exception:
                messages.error(request, "Error verifying reCAPTCHA.", extra_tags="register")
                return render(request, "index.html", {"reg_form": form, "login_form": LoginForm()})

            if not result.get("success"):
                messages.error(request, "reCAPTCHA validation failed.", extra_tags="register")
                return render(request, "index.html", {"reg_form": form, "login_form": LoginForm()})

            if User.objects.filter(email=email).exists():
                messages.error(request, "Email already registered.", extra_tags="register")
            elif User.objects.filter(username=username).exists():
                messages.error(request, "Username already taken.", extra_tags="register")
            else:
                user = User(username=username, email=email)
                user.set_password(password)
                user.save()
                auth_login(request, user)
                messages.success(request, "Account created successfully!", extra_tags="register")
                return redirect('dash')

    return render(request, "index.html", {
        "reg_form": form,
        "login_form": LoginForm(),
    })


def home(request):
    return render(request, "index.html", {
        "reg_form": RegistrationForm(),
        "login_form": LoginForm(),
    })
def settings(request):
    return render(request, "settings.html", {
        "update_form": UpdateForm(),
    })


def dash(request):
    user = request.user
    if user.is_authenticated:
        return render(request, "dash.html", {
            "update_form": UpdateForm(),
            "username": user.username,
            "email": user.email,
        })
    return redirect('home')


def subscriptions(request):
    return render(request, "sub.html", {})


def success(request):
    return render(request, "success.html", {})


def info(request):
    user = request.user
    return render(request, "info.html", {
        "username": user.username if user.is_authenticated else None,
        "email": user.email if user.is_authenticated else None,
    })


def Update(request):
    user = request.user
    if request.method == 'POST':
        form = UpdateForm(request.POST, instance=user)
        if form.is_valid():
            cd = form.cleaned_data
            user.username = cd.get("username")
            user.email = cd.get("email")
            password = cd.get("password")
            if password:
                user.set_password(password)
            user.save()
            return redirect('dash')
    else:
        form = UpdateForm(instance=user)

    return render(request, 'dash.html', {'form': form})


def create_checkout_session(request):
    if request.method == 'POST':
        try:
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': 'Beginner Course',
                        },
                        'unit_amount': 500,
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url="http://127.0.0.1:8000/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url="http://127.0.0.1:8000/sub",
            )
            return JsonResponse({'id': session.id})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)


def success(request):
    session_id = request.GET.get('session_id')

    if session_id and request.user.is_authenticated:
        try:
            session = stripe.checkout.Session.retrieve(session_id)
            if session.payment_status == 'paid':
                request.user.account_type = 'Beginner'
                request.user.save()
        except:
            pass

    context = {
        'plan_name': 'Beginner',
        'amount': '5.00',
    }
    return render(request, 'success.html', context)