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
from json_response import JsonResponse
from django.http import HttpResponse


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

def more(request):
    return render(request, "more.html", {})


def info(request):
    user = request.user
    return render(request, "info.html", {
        "username": user.username if user.is_authenticated else None,
        "email": user.email if user.is_authenticated else None,
        'plan_name': user.account_plan.name if user.is_authenticated else None,
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


@csrf_exempt
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    endpoint_secret = settings.STRIPE_WEBHOOK_SECRET

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError as e:

        return HttpResponse(status=400)


    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']


        customer_email = session.get('customer_email')


        plan_tier = session.get('metadata', {}).get('plan_tier', 'beginner')



        print(f"Payment successful for {customer_email} - Plan: {plan_tier}")

    return HttpResponse(status=200)

def create_checkout_session(request):
    if request.method == 'POST':
        try:
            course_tier = request.POST.get('course_tier')

            prices = {
                'beginner': {'amount': 4900, 'name': 'Beginner Course', 'display_price': '49.00'},
                'intermediate': {'amount': 9900, 'name': 'Intermediate Course', 'display_price': '99.00'},
                'advanced': {'amount': 14900, 'name': 'Advanced Course', 'display_price': '149.00'},
                'senior': {'amount': 24900, 'name': 'Senior Course', 'display_price': '249.00'}
            }

            selected_course = prices.get(course_tier, prices['beginner'])


            request.session['plan_name'] = selected_course['name']
            request.session['amount'] = selected_course['display_price']
            request.session['plan_tier'] = course_tier

            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': selected_course['name'],
                        },
                        'unit_amount': selected_course['amount'],
                    },
                    'quantity': 1,
                }],
                mode='payment',
                customer_email=request.user.email if request.user.is_authenticated else None,
                metadata={
                    'plan_tier': course_tier,
                    'user_id': request.user.id if request.user.is_authenticated else None,
                },
                success_url="https://course-hsuk.onrender.com/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url="https://course-hsuk.onrender.com/sub",
            )

            return redirect(session.url)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)


def success(request):
    plan_name = request.session.get('plan_name', 'Beginner Course')
    amount = request.session.get('amount', '49.00')
    plan_tier = request.session.get('plan_tier', 'beginner')

    context = {
        'plan_name': plan_name,
        'amount': amount,
        'user': request.user
    }

    return render(request, 'success.html', context)


