from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectMultipleField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from models import User  # Import User to validate uniqueness

class ProductForm(FlaskForm):
    model = StringField('Model', validators=[DataRequired(), Length(max=100)])
    color = StringField('Color', validators=[DataRequired(), Length(max=50)])
    memory = StringField('Memory', validators=[DataRequired(), Length(max=50)])
    serial_number = StringField('Serial Number', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('Add Product')

class UserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[
        Optional(),
        Length(min=6, message='Password should be at least 6 characters long.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        Optional(),
        EqualTo('password', message='Passwords must match.')
    ])
    roles = SelectMultipleField('Roles', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Submit')

    def __init__(self, original_email=None, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        self.original_email = original_email

    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email is already in use.')

    def validate(self, extra_validators=None):
        # Call the base class validate method
        if not super(UserForm, self).validate(extra_validators=extra_validators):
            return False

        # If password is being changed, ensure confirm_password is filled and matches
        if self.password.data:
            if not self.confirm_password.data:
                self.confirm_password.errors.append('This field is required.')
                return False
            if self.password.data != self.confirm_password.data:
                self.confirm_password.errors.append('Passwords must match.')
                return False

        return True

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message='Invalid email address.'),
        Length(max=150)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, message='Password should be at least 6 characters long.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message='Invalid email address.'),
        Length(max=150)
    ])
    password = PasswordField('Password', validators=[
        DataRequired()
    ])
    submit = SubmitField('Login')

class BugReportForm(FlaskForm):
    bug_details = TextAreaField('Bug Details', validators=[DataRequired()])
    submit = SubmitField('Submit')

class FeedbackForm(FlaskForm):
    feedback_details = TextAreaField('Feedback Details', validators=[DataRequired()])
    submit = SubmitField('Submit')
 