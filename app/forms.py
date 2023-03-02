from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField, RadioField, RadioField, BooleanField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, StopValidation
from wtforms.widgets import CheckboxInput, ListWidget

# Login form (subclassed from FlaskForm)
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class ChangePasswordForm(FlaskForm):
    old_pass = PasswordField('Old password', validators=[DataRequired()])
    new_pass = PasswordField('New password', validators=[DataRequired()])
    new_pass_retype = PasswordField('Retype new password', validators=[DataRequired()])
    submit = SubmitField('Change password')

class RegisterForm(FlaskForm):
    firstname = StringField('First name', validators=[DataRequired()])
    lastname = StringField('Last name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    passwordRetype = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class ProjectForm(FlaskForm):
    name = StringField('Project name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    color = RadioField('Color', choices=[
        ('red','Red'), ('blaze','Blaze'), ('orange','Orange'), ('dandelion','Dandelion'), ('yellow','Yellow'), ('chartreuse','Chartreuse'),
        ('green','Green'), ('emerald','Emerald'), ('teal ','Teal'), ('turquiose','Turquiose'), ('skyblue','Sky Blue'), ('blue','Blue'),
        ('deepblue','Deep Blue'), ('indigo','Indigo'), ('purple','Purple'), ('fuschia','Fuschia'), ('magenta','Magenta'), ('rose','Rose'),
    ], validators=[DataRequired()], default='rose')
    submit = SubmitField('Submit')

class CheckboxField(SelectMultipleField):
    widget = ListWidget(prefix_label=False)
    option_widget = CheckboxInput()

class CheckAtLeastOne():
    def __init__(self, message=None):
        if not message:
            message = 'At least one option must be selected.'
        self.message = message

    def __call__(self, form, field):
        if len(field.data) == 0:
            raise StopValidation(self.message)

class TaskForm(FlaskForm):
    name = StringField('Task Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    users = CheckboxField('Users', coerce = int, validators=[CheckAtLeastOne()])
    deadline = DateField('Due on', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ManageForm(FlaskForm):
    users = SelectField("New User:", coerce=int, validators=[DataRequired()])
    rank = BooleanField("Give User Leader Rank ", default=False, render_kw ={'checked':''})
    submit = SubmitField('Submit')

class EvaluationForm(FlaskForm):
#Question categories
    #Communication
    question1 = RadioField('This person effectively shared knowledge with other members of the team.',
        choices=[
            (1, 'Strongly Disagree'),
            (2, 'Disagree'),
            (3, 'Neutral'),
            (4, 'Agree'),
            (5, 'Strongly Agree')],
            validators=[DataRequired()])
    question2 = RadioField('This person provided constructive feedback to other team members regularly.',
        choices=[
            (1, 'Strongly Disagree'),
            (2, 'Disagree'),
            (3, 'Neutral'),
            (4, 'Agree'),
            (5, 'Strongly Agree')],
            validators=[DataRequired()])
    question3 = RadioField('This person attended scheduled meetings and contributed to team discussions.',
        choices=[
            (1, 'Strongly Disagree'),
            (2, 'Disagree'),
            (3, 'Neutral'),
            (4, 'Agree'),
            (5, 'Strongly Agree')],
            validators=[DataRequired()])
    #Performance
    question4 = RadioField('This person fully understood their role in the task at hand.',
        choices=[
            (1, 'Strongly Disagree'),
            (2, 'Disagree'),
            (3, 'Neutral'),
            (4, 'Agree'),
            (5, 'Strongly Agree')],
            validators=[DataRequired()])
    question5 = RadioField('This person contributed to the team and performed their role adequately.',
        choices=[
            (1, 'Strongly Disagree'),
            (2, 'Disagree'),
            (3, 'Neutral'),
            (4, 'Agree'),
            (5, 'Strongly Agree')],
            validators=[DataRequired()])
    question6 = RadioField('This person completed tasks in an appropriate and timely manner.',
        choices=[
            (1, 'Strongly Disagree'),
            (2, 'Disagree'),
            (3, 'Neutral'),
            (4, 'Agree'),
            (5, 'Strongly Agree')],
            validators=[DataRequired()])
    #Additional comments
    comment = TextAreaField('Additional comments or suggestions')
    submit = SubmitField('Submit')

class SubtaskForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    deadline = DateField('Due Date', validators=[DataRequired()])
    submit = SubmitField('Create')

class TransferOwnership(FlaskForm):
    new_owner = SelectField("New Project Owner:", validators=[DataRequired()], coerce=int)
    new_rank = RadioField("Your New Rank:", choices=[ ('Member', 'Member'), ("Leader",'Leader')], default = 'Leader')
    submit = SubmitField('I Understand,\nTransfer this Project')

class EditForm(FlaskForm):
    enable = BooleanField("Enabled", default=True, render_kw ={'checked':''})
    submit = SubmitField('Save Changes')

class MessageForm(FlaskForm):
    subject = StringField('Subject', validators=[DataRequired()])
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField("Send")
