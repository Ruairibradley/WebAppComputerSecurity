from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo

class RegisterForm(FlaskForm):
    """User registration form."""
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    name = StringField("Name", validators=[DataRequired(), Length(min=2, max=120)])
    phone = StringField("Phone", validators=[DataRequired(), Regexp(r"^[0-9+()\-\s]{7,}$")])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=12)])
    confirm = PasswordField(
        "Confirm",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")]
    )
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    """User login form."""
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    captcha = StringField("CAPTCHA")  # show after 3 failures
    submit = SubmitField("Login")

class TotpForm(FlaskForm): # sign up on first login then from there can use straight away
    """TOTP 2FA verification form."""
    totp = StringField("Authenticator code", validators=[DataRequired(), Regexp(r"^\d{6}$")])
    submit = SubmitField("Verify")

class ForgotForm(FlaskForm):
    """Password reset request form."""
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send reset link")

class ResetForm(FlaskForm):
    """Password reset form."""
    password = PasswordField("New password", validators=[DataRequired(), Length(min=12)])
    confirm = PasswordField(
        "Confirm",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")]
    )
    submit = SubmitField("Reset password")

class RequestEvalForm(FlaskForm):
    """Form for requesting an evaluation."""
    comment = StringField("Describe the object and request", validators=[DataRequired(), Length(max=2000)])
    contact_method = SelectField("Preferred contact", choices=[("email", "Email"), ("phone", "Phone")], validators=[DataRequired()])
    photo = FileField("Photo (jpg/png, ≤2MB)")
    submit = SubmitField("Submit request")

class DummyForm(FlaskForm):
    """A dummy form for CSRF protection only."""
    submit = SubmitField("Submit")
