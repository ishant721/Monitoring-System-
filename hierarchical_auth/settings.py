# hierarchical_auth/settings.py

from pathlib import Path
import os
from datetime import timedelta # For JWT token lifetime

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'django-insecure-a-default-secret-key-for-dev-if-not-set')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DJANGO_DEBUG', 'True').lower() == 'true'

ALLOWED_HOSTS_STRING = os.getenv('DJANGO_ALLOWED_HOSTS', '127.0.0.1,localhost,*') # Added * for dev
ALLOWED_HOSTS = [host.strip() for host in ALLOWED_HOSTS_STRING.split(',') if host.strip()]


# Application definition
INSTALLED_APPS = [
    'daphne',  # <-- ADDED for Channels real-time server
    'jazzmin',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    
    # Third-party apps
    'rest_framework',
    'rest_framework_simplejwt',
    'crispy_forms',
    "crispy_bootstrap5",
    'channels', # <-- ADDED for real-time functionality
    
    # Your apps
    'accounts', 
    'monitor_app',
    'mail_monitor',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware', # Manages sessions
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',         # CSRF protection
    'django.contrib.auth.middleware.AuthenticationMiddleware', # Django's session-based auth
    'accounts.middleware.JWTAuthenticationMiddleware',      # Your custom JWT auth
    'django.contrib.messages.middleware.MessageMiddleware',  # For flash messages
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'hierarchical_auth.urls'

SESSION_ENGINE = 'django.contrib.sessions.backends.db'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR / 'templates',  # This tells Django to look in your project-level 'templates' folder
        ],
        'APP_DIRS': True, # This allows Django to also find templates inside app-specific 'templates' folders
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'hierarchical_auth.wsgi.application'
ASGI_APPLICATION = 'hierarchical_auth.asgi.application'

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
        # "CONFIG": {
            # This points to your local Redis server.
            # The default port is 6379.
            # "hosts": [("127.0.0.1", 6379)],
        # },
    },
}


# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',},
]


# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Kolkata'
USE_I18N = True
USE_TZ = True

EMAIL_ENCRYPTION_KEY='5OJEWgSxtXW3NB5SEmut77ZNRARdSU1mUhxDIGqgMEQ='

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media') 


# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles_collected'

AGENT_API_KEY = "YOUR_SUPER_SECRET_AGENT_API_KEY"
AGENT_ONLINE_TIMEOUT_SECONDS = 30 # <-- ADDED

# Ensure this path is correct for your environment
MONITORING_RULES_FILE_PATH = os.path.join(BASE_DIR, 'monitoring_rules.json') # <-- MODIFIED for portability


# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --- Custom Application Settings ---

# Custom User Model
AUTH_USER_MODEL = 'accounts.CustomUser'

# Authentication URLs
LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'accounts:dashboard'
LOGOUT_REDIRECT_URL = 'accounts:login'

# DISALLOWED PUBLIC EMAIL DOMAINS
# Users cannot register or be created with emails from these domains.
# All other domains are implicitly considered "work" or "allowed" domains.
DISALLOWED_PUBLIC_EMAIL_DOMAINS = [
    # 'gmail.com',
    'yahoo.com',
    'hotmail.com',
    'outlook.com',
    'aol.com',
    'icloud.com',
    'live.com',
    'msn.com',
    'protonmail.com', # Example of another common free provider
    'zoho.com',       # Zoho has free personal tiers
    'gmx.com',
    'mail.com',
    # Add any other public/free email domains you want to block
    # If this list is empty, the validation logic in forms.py will allow all domains
    # (unless ImproperlyConfigured is raised for an empty list, depending on form logic).
]


# Crispy Forms Configuration
CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap5"
CRISPY_TEMPLATE_PACK = "bootstrap5"

# Django REST Framework
# hierarchical_auth/settings.py

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        # Use JWT for authenticating users who are accessing the web dashboard API.
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        
        # SessionAuthentication is good to have for browsing the API in a browser.
        'rest_framework.authentication.SessionAuthentication', 
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        # By default, require all API endpoints to be accessed by an authenticated user.
        'rest_framework.permissions.IsAuthenticated',
    )
}

# Simple JWT Configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': False,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'JWK_URL': None,
    'LEEWAY': 0,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',
    'JTI_CLAIM': 'jti',
    'AUTH_COOKIE': 'access_token',
    'AUTH_COOKIE_REFRESH': 'refresh_token',
    'AUTH_COOKIE_SECURE': os.getenv('DJANGO_AUTH_COOKIE_SECURE', 'False').lower() == 'true',
    'AUTH_COOKIE_HTTP_ONLY': True,
    'AUTH_COOKIE_SAMESITE': 'Lax',
}


# Email (SMTP) Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False
EMAIL_HOST_USER = 'ishantsingh01275@gmail.com'
EMAIL_HOST_PASSWORD = 'wrmsalhaoxsqcbaa'
DEFAULT_FROM_EMAIL = 'ishantsingh01275@gmail.com'




# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {'format': '{levelname} {asctime} {module} {message}', 'style': '{',},
        'simple': {'format': '{levelname} {message}', 'style': '{',},
    },
    'handlers': {
        'console': {'class': 'logging.StreamHandler', 'formatter': 'simple',},
    },
    'root': {'handlers': ['console'], 'level': 'INFO',},
    'loggers': {
        'django': {'handlers': ['console'], 'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'), 'propagate': False,},
        'accounts': {'handlers': ['console'], 'level': 'DEBUG', 'propagate': False,},
    },
}

# JAZZMIN SETTINGS
JAZZMIN_SETTINGS = {
    "site_title": "Monitoring System",
    "site_header": "Auth Admin",
    "site_brand": "Auth Panel",
    "welcome_sign": "Welcome to the Admin Panel",
    "copyright": "Your Company Ltd. All rights reserved.",
    "search_model": ["accounts.CustomUser", "auth.Group"],
    "topmenu_links": [
        {"name": "Admin Home", "url": "admin:index", "permissions": ["auth.view_user"]},
        {"model": "accounts.CustomUser", "name": "Manage Users"},
        {"name": "View Site", "url": "/", "new_window": True},
    ],
    "show_sidebar": True,
    "navigation_expanded": True,
    "order_with_respect_to": ["accounts", "accounts.customuser", "auth", "auth.group",],
    "icons": {
        "auth": "fas fa-users-cog", "auth.Group": "fas fa-users",
        "accounts": "fas fa-user-shield", "accounts.customuser": "fas fa-users",
    },
    "default_icon_parents": "fas fa-chevron-circle-right",
    "default_icon_children": "fas fa-circle",
    "related_modal_active": True,
    "show_ui_builder": True,
    "changeform_format": "horizontal_tabs",
    "language_chooser": False,
}

# JAZZMIN UI TWEAKS
JAZZMIN_UI_TWEAKS = {
    "navbar_small_text": False, "footer_small_text": False, "body_small_text": False,
    "brand_small_text": False, "brand_colour": "navbar-purple", "accent": "accent-primary",
    "navbar": "navbar-expand-lg navbar-dark navbar-purple", "no_navbar_border": False,
    "navbar_fixed": True, "layout_boxed": False, "footer_fixed": False, "sidebar_fixed": True,
    "sidebar": "sidebar-light-primary", "sidebar_nav_small_text": False,
    "sidebar_disable_expand": False, "sidebar_nav_child_indent": True,
    "sidebar_nav_compact_style": False, "sidebar_nav_legacy_style": False,
    "sidebar_nav_flat_style": True, "theme": "flatly", "dark_mode_theme": None,
    "button_classes": {
        "primary": "btn-primary", "secondary": "btn-secondary", "info": "btn-info",
        "warning": "btn-warning", "danger": "btn-danger", "success": "btn-success"
    },
    "actions_sticky_top": True
}