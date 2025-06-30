from django import forms
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, AuthenticationForm, SetPasswordForm
from .models import CustomUser, AdminFeatureRestrictions
from django.utils import timezone
from datetime import timedelta

try:
    from disposable_email_domains import blocklist as dea_domain_blocklist
except ImportError:
    dea_domain_blocklist = set() 
    print("WARNING: 'disposable-email-domains' library not found. DEA checking will be skipped.")


class WorkEmailDomainValidationMixin:
    """
    A mixin for forms that need to validate the email domain,
    allowing only emails from domains NOT in DISALLOWED_PUBLIC_EMAIL_DOMAINS
    and also checking against a DEA blocklist.
    """
    def _validate_email_domain(self, email_to_check):
        if not email_to_check:
            return 

        email_to_check = email_to_check.lower()
        domain = email_to_check.split('@')[-1]

        if domain in dea_domain_blocklist:
            raise forms.ValidationError(
                f"Registrations using temporary or disposable email services like '{domain}' are not permitted. "
                f"Please use a permanent work email address."
            )
        settings_disallowed_domains = getattr(settings, 'DISALLOWED_PUBLIC_EMAIL_DOMAINS', None)
        if settings_disallowed_domains is None:
            raise ImproperlyConfigured("The DISALLOWED_PUBLIC_EMAIL_DOMAINS setting is not defined in your settings.py.")

        if domain in settings_disallowed_domains:
            raise forms.ValidationError(
                f"Registrations from public email domains like '{domain}' are not allowed. "
                f"Please use a valid work email address."
            )
        return email_to_check


class CustomUserCreationForm(WorkEmailDomainValidationMixin, UserCreationForm):
    phone_number = forms.CharField(
        max_length=17, required=False,
        help_text='Optional. E.g., +12223334444',
        widget=forms.TextInput(attrs={'placeholder': 'E.g., +12223334444'})
    )

    def clean_phone_number(self):
        phone = self.cleaned_data.get('phone_number')
        if phone:
            # Remove spaces and check if another user has this phone number
            phone = phone.replace(' ', '')
            if CustomUser.objects.filter(phone_number=phone).exists():
                raise forms.ValidationError("This phone number is already registered.")
        return phone
    role = forms.ChoiceField(
        choices=[('', '--- Select Your Role ---')] + [(CustomUser.USER, 'User (Employee)'), (CustomUser.ADMIN, 'Admin (Company)')],
        required=True
    )
    company_admin_email = forms.EmailField(
        required=False,
        label="Company Admin's Email (Required if registering as Employee)",
        help_text="If registering as an Employee, enter your company Admin's registered and approved email."
    )
    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = ('email', 'first_name', 'last_name', 'role', 'phone_number', 'company_admin_email')

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not email: raise forms.ValidationError("Email address is required.")
        email = email.lower() 
        self._validate_email_domain(email) 
        if CustomUser.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email address already exists.")
        return email

    def clean_role(self):
        role = self.cleaned_data.get('role')
        if role not in [CustomUser.USER, CustomUser.ADMIN]:
            raise forms.ValidationError("Invalid role selected for registration.")
        return role

    def clean(self):
        cleaned_data = super().clean()
        role = cleaned_data.get('role')
        company_admin_email = cleaned_data.get('company_admin_email')

        if company_admin_email: 
            cleaned_data['company_admin_email'] = company_admin_email.lower()

        if role == CustomUser.USER:
            if not company_admin_email:
                self.add_error('company_admin_email', "This field is required if you are registering as a User (Employee).")
            else:
                try:
                    admin = CustomUser.objects.get(email__iexact=cleaned_data['company_admin_email'], role=CustomUser.ADMIN, is_active=True)
                    if not admin.is_admin_access_active: # Check if the found admin's own access is active
                        self.add_error('company_admin_email', f"The specified Company Admin ({admin.email}) account access is currently inactive.")
                    else:
                        cleaned_data['company_admin_instance'] = admin
                except CustomUser.DoesNotExist:
                    self.add_error('company_admin_email', "No active and approved Admin (Company) found with this email.")
        elif role == CustomUser.ADMIN and company_admin_email:
            self.add_error('company_admin_email', "Admins (Company role) should not specify a Company Admin Email during their own registration.")
            cleaned_data['company_admin_email'] = None
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.role = self.cleaned_data['role']
        if user.role == CustomUser.USER:
            user.company_admin = self.cleaned_data.get('company_admin_instance')
        # Model's default for is_active is False. It's set True upon approval.
        if commit:
            user.save()
        return user


class CustomUserChangeForm(WorkEmailDomainValidationMixin, UserChangeForm): # For Django Admin
    class Meta(UserChangeForm.Meta):
        model = CustomUser
        fields = (
            'email', 'first_name', 'last_name', 'phone_number', 'role', 
            'is_active', 'is_staff', 'is_superuser', 'is_email_verified',
            'company_admin', 'approved_by', 
            'max_allowed_users', 'admin_account_type', 'access_ends_at', 
            'access_granted_by', 'trial_extension_requested', 'trial_extension_reason',
            'groups', 'user_permissions'
        )

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            email = email.lower()
            if self.instance.pk and self.instance.email.lower() != email: # If email has changed for an existing user
                # self._validate_email_domain(email) # Optional: re-validate domain on change
                if CustomUser.objects.filter(email__iexact=email).exclude(pk=self.instance.pk).exists():
                    raise forms.ValidationError("This email address is already in use by another account.")
        return email


class CustomAuthenticationForm(AuthenticationForm):
    username = forms.EmailField(label="Email", widget=forms.EmailInput(attrs={'autofocus': True, 'class': 'form-control'}))
    password = forms.CharField(label="Password", strip=False, widget=forms.PasswordInput(attrs={'autocomplete': 'current-password', 'class': 'form-control'}))

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if username:
            username = username.lower()
            # Check if user exists
            try:
                user = CustomUser.objects.get(email__iexact=username)
                if not user.is_active:
                    raise forms.ValidationError("This account is inactive. Please contact your administrator.")
                if not user.is_email_verified:
                    raise forms.ValidationError("Email address not verified. Please verify your email first.")
            except CustomUser.DoesNotExist:
                pass  # This will be handled by authenticate()
        return username

    def confirm_login_allowed(self, user):
        super().confirm_login_allowed(user) 
        if not isinstance(user, CustomUser):
            raise forms.ValidationError("Authentication error: Invalid user profile.", code='invalid_user_type')

        if user.role == CustomUser.ADMIN:
            if not user.is_admin_access_active: 
                raise forms.ValidationError(
                    f"Your Admin account access ({user.get_admin_account_type_display()}) has expired or is currently inactive. Please contact support.",
                    code='admin_access_inactive'
                )
        elif user.role == CustomUser.SUPERADMIN:
            if not user.is_email_verified:
                 raise forms.ValidationError("SUPERADMIN account email requires verification.", code='superadmin_email_not_verified')
        elif user.role == CustomUser.USER:
            if not user.is_email_verified:
                raise forms.ValidationError("Your email address has not been verified.", code='email_not_verified')
            if not user.approved_by: 
                raise forms.ValidationError("Your account is awaiting approval.", code='awaiting_approval')
            if not user.is_active: 
                raise forms.ValidationError("This account is inactive.", code='inactive_user')
        else:
             raise forms.ValidationError("Unknown user role, login denied.", code='unknown_role')


class OTPVerificationForm(forms.Form):
    otp = forms.CharField(max_length=6, required=True, label="OTP Code", widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter OTP from email'}))


class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(label="Registered Email Address", widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your email'}))
    def clean_email(self):
        email = self.cleaned_data.get('email','').lower()
        if not email: raise forms.ValidationError("Email is required.")
        try: user = CustomUser.objects.get(email__iexact=email)
        except CustomUser.DoesNotExist: return email 
        if not user.is_active: raise forms.ValidationError("Account inactive. Password cannot be reset.")
        if not user.is_email_verified: raise forms.ValidationError("Email not verified. Password cannot be reset via this email.")
        return email


class SetNewPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(label="New password", widget=forms.PasswordInput(attrs={'autocomplete': 'new-password', 'class': 'form-control'}), strip=False)
    new_password2 = forms.CharField(label="Confirm new password", strip=False, widget=forms.PasswordInput(attrs={'autocomplete': 'new-password', 'class': 'form-control'}))


class SuperadminAddAdminForm(WorkEmailDomainValidationMixin, forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'autocomplete': 'new-password', 'class': 'form-control'}), label="Initial Password")
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'autocomplete': 'new-password', 'class': 'form-control'}), label="Confirm Password")

    admin_account_type_initial = forms.ChoiceField(
        choices=[(c.value, c.label) for c in CustomUser.AdminAccountType if c not in [CustomUser.AdminAccountType.NONE, CustomUser.AdminAccountType.EXPIRED]],
        label="Initial Account Type", required=True, widget=forms.Select(attrs={'class': 'form-select'})
    )
    access_duration_days = forms.IntegerField(
        label="Access Duration (days)", required=False, min_value=1,
        help_text="Required if Trial or time-limited Subscription. Blank for indefinite Subscription.",
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder':'e.g., 7 for Trial, 365 for Subscription'})
    )
    max_allowed_users_initial = forms.IntegerField(
        label="Initial Max Allowed Users", required=False, min_value=0, initial=0,
        help_text="Default is 0. Set user limit for this Admin.",
        widget=forms.NumberInput(attrs={'class': 'form-control'})
    )

    class Meta:
        model = CustomUser
        fields = ['email', 'first_name', 'last_name', 'phone_number', 
                  'password', 'confirm_password', 
                  'admin_account_type_initial', 'access_duration_days', 'max_allowed_users_initial']
        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Optional E.g., +12223334444'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['phone_number'].required = False
        self.fields['max_allowed_users_initial'].required = False
        self.fields['access_duration_days'].required = False 

    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower()
        if not email: raise forms.ValidationError("Email cannot be blank.")
        self._validate_email_domain(email)
        if CustomUser.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password"); confirm_password = cleaned_data.get("confirm_password")
        if password and confirm_password and password != confirm_password: self.add_error('confirm_password', "Passwords do not match.")

        account_type = cleaned_data.get('admin_account_type_initial')
        duration = cleaned_data.get('access_duration_days')
        max_users = cleaned_data.get('max_allowed_users_initial')

        if account_type == CustomUser.AdminAccountType.TRIAL and (not duration or duration <= 0):
            self.add_error('access_duration_days', "Trial accounts require a positive duration in days (e.g., 7).")

        if account_type == CustomUser.AdminAccountType.SUBSCRIBED and duration is not None and duration <= 0:
            self.add_error('access_duration_days', "Subscription duration must be positive if set, or leave blank for indefinite access.")

        if max_users is None: 
            cleaned_data['max_allowed_users_initial'] = 0 # Default to 0 if not provided

        return cleaned_data

    def save(self, commit=True, added_by_superadmin=None):
        user = super(SuperadminAddAdminForm, self).save(commit=False)
        user.email = self.cleaned_data['email']
        user.set_password(self.cleaned_data["password"])
        user.role = CustomUser.ADMIN
        user.is_staff = False; user.is_superuser = False
        user.is_email_verified = True; user.is_active = True 
        user.approved_by = added_by_superadmin

        user.admin_account_type = self.cleaned_data.get('admin_account_type_initial')
        user.max_allowed_users = self.cleaned_data.get('max_allowed_users_initial', 0)
        user.access_granted_by = added_by_superadmin

        duration = self.cleaned_data.get('access_duration_days')
        if duration and duration > 0:
            user.access_ends_at = timezone.now() + timedelta(days=duration)
        elif user.admin_account_type == CustomUser.AdminAccountType.SUBSCRIBED and not duration: 
            user.access_ends_at = None # Indefinite subscription
        else: 
            user.access_ends_at = None 

        if commit:
            user.save() # Model's save method will handle side-effects like deactivating users
        return user


class SuperadminManageAdminAccessForm(forms.ModelForm):
    new_max_allowed_users = forms.IntegerField(
        label="Set Max Allowed Users", required=False, min_value=0, 
        widget=forms.NumberInput(attrs={'class': 'form-control form-control-sm'})
    )
    new_access_duration_days = forms.IntegerField(
        label="Set/Extend Access For (Days from now)", required=False, min_value=0, 
        help_text="0 days ends access now. Blank for indefinite subscription.",
        widget=forms.NumberInput(attrs={'class': 'form-control form-control-sm'})
    )
    class Meta:
        model = CustomUser
        fields = ['admin_account_type', 'new_max_allowed_users', 'new_access_duration_days']
        widgets = {'admin_account_type': forms.Select(attrs={'class': 'form-select form-select-sm'})}
        labels = {'admin_account_type': "Account Type"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields['admin_account_type'].initial = self.instance.admin_account_type
            # Pre-fill with current max_allowed_users. If superadmin clears this field,
            # clean method will default it to 0 for active types or enforce 0 for EXPIRED.
            self.fields['new_max_allowed_users'].initial = self.instance.max_allowed_users 

    def clean(self):
        cleaned_data = super().clean()
        account_type = cleaned_data.get('admin_account_type')
        duration = cleaned_data.get('new_access_duration_days')
        max_users_input = cleaned_data.get('new_max_allowed_users') # Value from the input field

        if account_type == CustomUser.AdminAccountType.TRIAL and (duration is None or duration <= 0):
            self.add_error('new_access_duration_days', "Trial accounts require a positive duration (e.g., 7 days).")

        if account_type == CustomUser.AdminAccountType.SUBSCRIBED and duration is not None and duration < 0: 
            self.add_error('new_access_duration_days', "Subscription duration cannot be negative. Use 0 to end now, or leave blank for indefinite.")

        if account_type == CustomUser.AdminAccountType.EXPIRED:
            # If EXPIRED is selected, new_max_allowed_users in cleaned_data MUST be 0.
            # And duration is not applicable for setting, view will set access_ends_at to now.
            if max_users_input is not None and max_users_input > 0:
                 self.add_error('new_max_allowed_users', "Expired accounts must have Max Allowed Users set to 0.")
            cleaned_data['new_max_allowed_users'] = 0 
            cleaned_data['new_access_duration_days'] = 0 # Interpret as "ends now"

        elif account_type == CustomUser.AdminAccountType.NONE: # Should not be an option to select for existing
            self.add_error('admin_account_type', "Cannot set Account Type to 'Not Set'. Choose a valid type.")

        # If max_users field was left blank by superadmin (comes in as None for IntegerField)
        # and the account type is not being set to EXPIRED, default it to 0.
        # If a number was entered, that number will be in max_users_input.
        if max_users_input is None and account_type not in [CustomUser.AdminAccountType.EXPIRED, CustomUser.AdminAccountType.NONE]:
            cleaned_data['new_max_allowed_users'] = 0 

        return cleaned_data




class AdminTrialExtensionRequestForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['trial_extension_reason']
        widgets = {
            'trial_extension_reason': forms.Textarea(attrs={'rows': 3, 'class': 'form-control', 'placeholder': 'Please provide a reason for requesting a trial extension.'}),
        }
        labels = {
            'trial_extension_reason': "Reason for Extension Request (minimum 10 characters)"
        }

    def clean_trial_extension_reason(self):
        reason = self.cleaned_data.get('trial_extension_reason','').strip()
        if len(reason) < 10:
            raise forms.ValidationError("Please provide a brief reason (at least 10 characters).")
        return reason


class SuperadminTrialExtensionForm(forms.Form):
    extension_days = forms.IntegerField(
        min_value=1,
        max_value=365,
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Days to extend'})
    )


class AgentMonitoringConfigForm(forms.Form):
    # Default features (enabled by default)
    is_activity_monitoring_enabled = forms.BooleanField(
        required=False, 
        initial=True,
        label="Activity Monitoring",
        help_text="Track active windows and applications"
    )
    is_network_monitoring_enabled = forms.BooleanField(
        required=False, 
        initial=True,
        label="Network Monitoring", 
        help_text="Monitor network usage and data transfer"
    )
    is_screenshot_capturing_enabled = forms.BooleanField(
        required=False, 
        initial=True,
        label="Screenshot Capturing",
        help_text="Capture periodic screenshots"
    )
    capture_interval_seconds = forms.IntegerField(
        initial=10,
        min_value=5,
        max_value=300,
        label="Screenshot Interval (seconds)",
        help_text="How often to capture screenshots (5-300 seconds)"
    )

    # Optional features (disabled by default)
    is_live_streaming_enabled = forms.BooleanField(
        required=False,
        initial=False,
        label="Live Streaming",
        help_text="Enable real-time screen streaming"
    )
    is_video_recording_enabled = forms.BooleanField(
        required=False,
        initial=False,
        label="Video Recording",
        help_text="Record screen activity as video files"
    )
    is_keystroke_logging_enabled = forms.BooleanField(
        required=False,
        initial=False,
        label="Keystroke Logging",
        help_text="Log keyboard input (use with caution)"
    )
    is_email_monitoring_enabled = forms.BooleanField(
        required=False,
        initial=False,
        label="Email Monitoring",
        help_text="Monitor user's email activity"
    )


class AdminFeatureRestrictionsForm(forms.ModelForm):
    """Form for superadmins to manage feature restrictions for admin companies"""

    class Meta:
        model = AdminFeatureRestrictions
        fields = [
            'can_use_activity_monitoring',
            'can_use_network_monitoring', 
            'can_use_screenshot_capturing',
            'can_use_live_streaming',
            'can_use_video_recording',
            'can_use_keystroke_logging',
            'can_use_email_monitoring',
            'can_configure_monitoring',
            'can_manage_email_config',
            'max_screenshot_retention_days',
            'max_video_retention_days',
        ]

        widgets = {
            'max_screenshot_retention_days': forms.NumberInput(attrs={'min': 1, 'max': 365}),
            'max_video_retention_days': forms.NumberInput(attrs={'min': 1, 'max': 90}),
        }

        labels = {
            'can_use_activity_monitoring': 'Activity Monitoring',
            'can_use_network_monitoring': 'Network Monitoring',
            'can_use_screenshot_capturing': 'Screenshot Capturing',
            'can_use_live_streaming': 'Live Streaming (Premium)',
            'can_use_video_recording': 'Video Recording (Premium)',
            'can_use_keystroke_logging': 'Keystroke Logging (Premium)',
            'can_use_email_monitoring': 'Email Monitoring (Premium)',
            'can_configure_monitoring': 'Configure Monitoring Settings',
            'can_manage_email_config': 'Manage Email Configuration',
            'max_screenshot_retention_days': 'Screenshot Retention (Days)',
            'max_video_retention_days': 'Video Retention (Days)',
        }

        help_texts = {
            'can_use_activity_monitoring': 'Allow basic activity and window tracking',
            'can_use_network_monitoring': 'Allow monitoring network usage',
            'can_use_screenshot_capturing': 'Allow capturing periodic screenshots',
            'can_use_live_streaming': 'Allow real-time screen streaming (premium feature)',
            'can_use_video_recording': 'Allow screen recording (premium feature)',
            'can_use_keystroke_logging': 'Allow keystroke logging (premium feature)',
            'can_use_email_monitoring': 'Allow email monitoring (premium feature)',
            'can_configure_monitoring': 'Allow admin to configure monitoring settings for users',
            'can_manage_email_config': 'Allow admin to set up email monitoring configuration',
            'max_screenshot_retention_days': 'Maximum days to keep screenshots (1-365)',
            'max_video_retention_days': 'Maximum days to keep video recordings (1-90)',
        }


class AdminAddUserForm(WorkEmailDomainValidationMixin, forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'autocomplete': 'new-password', 'class': 'form-control'}), label="Initial Password")
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'autocomplete': 'new-password', 'class': 'form-control'}), label="Confirm Password")

    class Meta:
        model = CustomUser
        fields = ['email', 'first_name', 'last_name', 'phone_number', 'password', 'confirm_password']
        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Optional E.g., +12223334444'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['phone_number'].required = False

    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower()
        if not email: raise forms.ValidationError("Email cannot be blank.")
        self._validate_email_domain(email)
        if CustomUser.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password"); confirm_password = cleaned_data.get("confirm_password")
        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', "Passwords do not match.")
        return cleaned_data

    def save(self, commit=True, added_by_admin=None, company_admin_instance=None):
        user = super(AdminAddUserForm, self).save(commit=False) # Call ModelForm's save
        user.email = self.cleaned_data['email']
        user.set_password(self.cleaned_data["password"])
        user.role = CustomUser.USER
        user.company_admin = company_admin_instance
        user.is_email_verified = True 
        user.is_active = True       
        if added_by_admin:
            user.approved_by = added_by_admin
        if commit:
            user.save()
        return user