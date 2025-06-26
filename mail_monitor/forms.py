# mail_monitor/forms.py

from django import forms
from .models import CompanyEmailConfig

# ==============================================================================
#  FORM FOR THE ADMIN
# ==============================================================================
class CompanyEmailConfigForm(forms.ModelForm):
    """
    A comprehensive form for the Admin to configure the company-wide email 
    server settings. It directly maps to the CompanyEmailConfig model.
    """
    class Meta:
        model = CompanyEmailConfig
        fields = ['imap_server', 'imap_port', 'smtp_server', 'smtp_port']
        
        labels = {
            'imap_server': "Company's IMAP Server Address",
            'imap_port': "IMAP Port (e.g., 993 for SSL)",
            'smtp_server': "SMTP Server Address (Optional, for sent mail)",
            'smtp_port': "SMTP Port (e.g., 587 for TLS or 465 for SSL)",
        }

        help_texts = {
            'imap_server': "Example: imap.gmail.com or outlook.office365.com",
            'smtp_server': "Example: smtp.gmail.com or smtp.office365.com",
        }
        
        widgets = {
            'imap_server': forms.TextInput(attrs={'placeholder': 'e.g., imap.gmail.com'}),
            'smtp_server': forms.TextInput(attrs={'placeholder': 'e.g., smtp.gmail.com'}),
            'imap_port': forms.NumberInput(attrs={'placeholder': '993'}),
            'smtp_port': forms.NumberInput(attrs={'placeholder': '587'}),
        }


# ==============================================================================
#  FORM FOR THE USER
# ==============================================================================
class UserAppPasswordForm(forms.Form):
    """
    A very simple form for the end-user. It only asks for the one piece
    of information they need to provide: their App Password. All other
    settings are inherited from their admin's configuration.
    """
    app_password = forms.CharField(
        label="Your Email App Password",
        widget=forms.PasswordInput(attrs={
            'autocomplete': 'new-password', 
            'placeholder': 'Enter the 16-digit App Password you generated'
        }),
        required=True,
        help_text="For security, please generate and use an App Password from your email provider, not your main account password."
    )