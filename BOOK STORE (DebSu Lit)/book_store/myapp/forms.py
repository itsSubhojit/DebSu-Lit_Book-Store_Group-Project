import re
from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.core.exceptions import ValidationError
from .models import CustomUser, Student


class MyRegFrm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ('username', 'first_name', 'last_name', 'email', 'mobile')

    def clean_username(self):
        username = self.cleaned_data.get('username', '').strip()
        if not username:
            raise ValidationError("Username is required.")
        if CustomUser.objects.filter(username__iexact=username).exists():
            raise ValidationError("This username is already taken. Please choose another.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        if not email:
            raise ValidationError("Email address is required.")
        if CustomUser.objects.filter(email__iexact=email).exists():
            raise ValidationError("An account with this email address already exists.")
        return email

    def clean_mobile(self):
        mobile = self.cleaned_data.get('mobile', '').strip()
        if not mobile:
            raise ValidationError("Mobile number is required.")
        if not re.match(r'^\d{10}$', mobile):
            raise ValidationError("Mobile number must be exactly 10 digits.")
        if CustomUser.objects.filter(mobile=mobile).exists():
            raise ValidationError("This mobile number is already registered.")
        return mobile

    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        if not password:
            raise ValidationError("Password is required.")
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter (A-Z).")
        if not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain at least one lowercase letter (a-z).")
        if not re.search(r'[0-9]', password):
            raise ValidationError("Password must contain at least one digit (0-9).")
        if not re.search(r'[@$!%*?&#^()_+=\-{}\[\]:;"\'<>,./]', password):
            raise ValidationError("Password must contain at least one special character (e.g. @, $, !, %, etc.).")
        return password


class StdRegFrm(forms.ModelForm):
    class Meta:
        model = Student
        fields = ('name', 'email', 'mobile')


class MyChngFrm(UserChangeForm):
    password = None
    username = None

    first_name = forms.CharField(
        label="First Name",
        required=False,
        widget=forms.TextInput(attrs={'class': 'dsl-form-input', 'placeholder': 'First name'})
    )
    last_name = forms.CharField(
        label="Last Name",
        required=False,
        widget=forms.TextInput(attrs={'class': 'dsl-form-input', 'placeholder': 'Last name'})
    )
    email = forms.EmailField(
        label="Email Address",
        required=True,
        widget=forms.EmailInput(attrs={'class': 'dsl-form-input', 'placeholder': 'you@example.com'})
    )
    mobile = forms.CharField(
        label="Contact Number (10 digits)",
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'dsl-form-input',
            'placeholder': '9876543210',
            'maxlength': '10',
            'pattern': r'\d{10}'
        })
    )
    address_line1 = forms.CharField(
        label="Flat / House / Apartment No.",
        required=False,
        widget=forms.TextInput(attrs={'class': 'dsl-form-input', 'placeholder': 'Flat 101, Palm Grove'})
    )
    address_line2 = forms.CharField(
        label="Street / Road / Area",
        required=False,
        widget=forms.TextInput(attrs={'class': 'dsl-form-input', 'placeholder': 'Main Road, Indiranagar'})
    )
    city = forms.CharField(
        label="City",
        required=False,
        widget=forms.TextInput(attrs={'class': 'dsl-form-input', 'placeholder': 'Bengaluru'})
    )
    state = forms.CharField(
        label="State",
        required=False,
        widget=forms.TextInput(attrs={'class': 'dsl-form-input', 'placeholder': 'Karnataka'})
    )
    pincode = forms.CharField(
        label="PIN Code (6 digits)",
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'dsl-form-input',
            'placeholder': '560038',
            'maxlength': '6'
        })
    )

    class Meta:
        model = CustomUser
        fields = (
            'first_name', 'last_name', 'email', 'mobile',
            'address_line1', 'address_line2',
            'city', 'state', 'pincode'
        )

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        if not email:
            raise ValidationError("Email address is required.")
        # If user did not change their email, allow it without duplicate conflict
        if self.instance and self.instance.pk and self.instance.email and self.instance.email.strip().lower() == email:
            return email
        qs = CustomUser.objects.filter(email__iexact=email)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise ValidationError("An account with this email address already exists.")
        return email

    def clean_mobile(self):
        mobile = self.cleaned_data.get('mobile', '').strip()
        if not mobile:
            raise ValidationError("Mobile number is required.")
        if not re.match(r'^\d{10}$', mobile):
            raise ValidationError("Mobile number must be exactly 10 digits.")
        # If user did not change their mobile, allow it without duplicate conflict
        if self.instance and self.instance.pk and self.instance.mobile and self.instance.mobile.strip() == mobile:
            return mobile
        qs = CustomUser.objects.filter(mobile=mobile)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise ValidationError("This mobile number is already in use by another account.")
        return mobile
