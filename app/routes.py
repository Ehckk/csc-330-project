from datetime import date, datetime
from app import app
from datetime import date
from flask import render_template, redirect, url_for, session
from flask_login import login_user, logout_user, current_user, login_required
from app.forms import EvaluationForm, LoginForm, ChangePasswordForm, ProjectForm, RegisterForm, TaskForm, TransferOwnership, ManageForm, SubtaskForm, MessageForm
from app.models import Users, Projects, Roles, Tasks, Subtasks, Assignments, Changes, Forms, Evaluations, Questions, Messages
from string import capwords
from app import db
import sqlalchemy as sa
import sys
import re

normalize = lambda x: capwords(x.replace("_", " "))
fmtTime = lambda x: x.strftime("%b %d, %Y")
fmtDate = lambda x: datetime.strptime(x, "%b %d, %Y")
categories = ['Communication', 'Feedback', 'Attendance', 'Responsibility', 'Performance', 'Efficiency']
fmtAction = {
    'override': '',
    'request': 'requested to',
    'confirm': 'confirmed the request to',
    'deny': 'denied the request to'
}
fmtRequest = {
    'start': 'started',
    'skip': 'skipped',
    'submit': 'submitted'
}

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for('view_projects')), 404

@app.route('/404', methods=['GET'])
def not_found():
    return render_template('not_found.html')

def check_prev_urls(url):
    for (i, link) in enumerate(session['urls']):
        if link['url'] == url:
            del session['urls'][i]
            break

def update_prev_urls(url, label, sub=None):
    check_prev_urls(url)
    session['urls'].insert(0, { 'url': url, 'label': label, 'sub': sub })
    if len(session['urls']) > 5:
        session['urls'].pop()
    session.modified = True

@app.route('/', methods=['GET', 'POST'])
def index():
    # Authenticated users are redirected to home page.
    if current_user.is_authenticated:
        return redirect(url_for('view_projects'))
    form = LoginForm()
    if form.validate_on_submit():
        # Query DB for user by username
        username = form.username.data
        user = db.session.query(Users).filter_by(username=username).first()
        if user is None:
            form.username.data = ''
            form.password.data = ''
            return render_template('index.html', form=form, msg=f'No user found with username "{username}"')
        if not user.check_password(form.password.data):
            form.username.data = ''
            form.password.data = ''
            return render_template('index.html', form=form, msg=f"Incorrect Password")
        # login_user is a flask_login function that starts a session
        login_user(user)
        session['urls'] = []
        return redirect(url_for('view_projects'))
    return render_template('index.html', form=form, msg=None)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password = form.password.data
        if password != form.passwordRetype.data:
            return render_template('register.html',
                form=form, msg="Passwords do not match")
        if len(password)<8 or len(password)>24:
            return render_template('register.html',
                form=form, msg='Password must be between 8 and 24 characters')

        email = form.email.data
        if not re.match(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+', email):
            return render_template('register.html',
                form=form, msg='Invalid email address')
        email_check = db.session.query(Users).filter_by(email=email).first()
        if email_check is not None:
            return render_template('register.html',
                form=form, msg='Email address already taken')

        username = form.username.data
        if len(username)<4 or len(username)>16:
            return render_template('register.html',
                form=form, msg='Username must be between 4 and 16 characters')
        if not re.match(r'^[a-zA-Z0-9]+(_[a-zA-Z0-9]+)?$', username):
            return render_template('register.html',
                form=form, msg='Username must be alphanumeric or be separated by an underscore')

        firstname = form.firstname.data
        if len(firstname)<1 or len(firstname)>32:
            return render_template('register.html',
                form=form, msg='First name must be between 1 and 32 characters')
        if not re.match(r'^[a-zA-Z]+(-[a-zA-Z]+)?$', firstname):
            return render_template('register.html',
                form=form, msg='First name must contain only letters or be separated by a hyphen')

        lastname = form.lastname.data
        if len(lastname)<1 or len(lastname)>32:
            return render_template('register.html',
                form=form, msg='Last name must be between 1 and 32 characters')
        if not re.match(r'^[a-zA-Z]+(-[a-zA-Z]+)?$', lastname):
            return render_template('register.html',
                form=form, msg='Last name must contain only letters or be separated by a hyphen')

        user = db.session.query(Users).filter_by(username=username).first()
        if user is not None:
            return render_template('register.html',
                form=form, msg='Username is already taken')
        if user is None:
            user = Users(
                username = form.username.data,
                password = form.password.data,
                firstname = form.firstname.data,
                lastname = form.lastname.data,
                email = form.email.data
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            msg = 'Registraton successful'
            session['urls'] = []
            return redirect(url_for('index'))
    return render_template('register.html', form=form, msg=None)

@app.route('/projects', methods=['GET', 'POST'])
@login_required
def view_projects():
    form = ProjectForm()
    return render_template('projects/view_all.html', prev_urls=session['urls'], form=form, msg_form=MessageForm(),
                           user=user_data(current_user.id), projects=project_data_all(current_user.id))

@app.route('/project/<pid>/manage', methods=['GET', 'POST'])
@login_required
def manage_project(pid):
    form = ProjectForm()
    transfer_form = TransferOwnership()
    project = project_data(pid)
    user = user_data(current_user.id, pid)
    if user['rank'] != 'Owner': return redirect(url_for('view_tasks', pid=project['pid']))
    possible_owners = list(filter(lambda user: user['id'] != current_user.id, project['users']))
    transfer_form.new_owner.choices = [(user['id'], f"{user['firstname']} {user['lastname']}") for user in possible_owners]
    form.name.data = project['name']
    form.description.data = project['description']
    form.color.data = project['color']
    update_prev_urls(f"/project/{pid}/manage", f"Settings", project['name'])
    return render_template('projects/manage.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           form=form, transfer_form=transfer_form, project=project, user=user)

@app.route('/project/<pid>/tasks')
@login_required
def view_tasks(pid):
    project = project_data(pid)
    user = user_data(current_user.id, pid)
    incomplete = task_data_all(pid, status_type='incomplete', days_until_due=True)
    complete = task_data_all(pid, status_type='complete', days_until_due=True)
    update_prev_urls(f"/project/{pid}/tasks", f"Your Tasks", project['name'])
    return render_template('tasks/view_all.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           user=user, project=project, incomplete=incomplete, complete=complete)

def get_task_requests(task):
    requests = { 'pending': [], 'start': [], 'skip': [], 'submit': [] }
    for assignment in task['assignments']:
        if assignment['request'] is None:
            requests['pending'].append(assignment)
        else:
            requests[assignment['request'].lower()].append(assignment)
    current_request = None
    for (request, assignments) in requests.items():
        if request != 'pending':
            if current_request is None:
                if len(assignments) > 0:
                    current_request = request
                    break
    return current_request, requests

@app.route('/project/<pid>/tasks/<tid>')
@login_required
def view_task(pid, tid):
    project = project_data(pid)
    user=user_data(current_user.id, pid)
    task=task_data(pid, tid, with_extra_data=True)
    form = TaskForm()
    form.name.data = task['name']
    form.description.data = task['name']
    form.users.choices = [(user['id'], f"{user['firstname']} {user['lastname']}") for user in project['users']]
    task_users = [assignment['user']['id'] for assignment in task['assignments']]
    form.users.data = task_users
    form.deadline.data = datetime.strptime(task['deadline'], "%b %d, %Y")
    form.submit.label.text = 'Save Changes'
    subtask_form = SubtaskForm()
    (current_request, requests) = get_task_requests(task)
    assignment = db.session.query(Assignments).filter(Assignments.id == current_user.id, Assignments.tid == tid).first()
    is_on_task = assignment is not None
    has_confirmed = False
    if is_on_task:
        has_confirmed = assignment.request is not None
    update_prev_urls(f"/project/{pid}/tasks/{tid}", f"{task['name']}", project['name'])
    return render_template('/tasks/view.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           form=form, subtask_form=subtask_form,
                           project=project, user=user, task=task, task_users=task_users,
                           current_request=current_request, requests=requests,
                           is_on_task=is_on_task, has_confirmed=has_confirmed)

@app.route('/project/<pid>/tasks/manage')
@login_required
def manage_tasks(pid):
    project=project_data(pid)
    user=user_data(current_user.id, pid)
    tasks=task_data_all(pid, only_assigned_tasks=False)
    form = TaskForm()
    form.users.choices = [(user['id'], f"{user['firstname']} {user['lastname']}") for user in project['users']]
    update_prev_urls(f"/project/{pid}/tasks/manage", f"Manage Tasks", project['name'])
    return render_template('tasks/manage.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           form=form, project=project, user=user, tasks=tasks)

@app.route('/project/<pid>/users/<id>')
@login_required
def view_user(pid, id):
    target = db.session.query(Users.id).join(Roles, Roles.id == id)\
        .filter(Users.id == id, Roles.pid == pid).first()
    if target is None: return redirect(url_for('not_found'))
    project=project_data(pid)
    user=user_data(current_user.id, pid)
    target=user_data(id, pid)
    tasks=task_data_all(pid)
    other_tasks=task_data_all(pid, other_id=id,  days_until_due=True)
    common_tasks = []
    for task in tasks:
        if task in other_tasks:
            common_tasks.append(task)
    update_prev_urls(f"/project/{pid}/users/{id}", f"{target['firstname']} {target['lastname']}", project['name'])
    return render_template('users/view.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           project=project, user=user, target=user_data(id, pid), common_tasks=common_tasks)

@app.route('/project/<pid>/users')
@login_required
def view_users(pid):
    project=project_data(pid)
    user=user_data(current_user.id, pid)
    project_users = db.session.query(Users.id)\
        .join(Roles, Roles.id == Users.id)\
        .filter(Roles.pid==pid).subquery()
    non_project_users = db.session.query(Users)\
        .filter(sa.not_(Users.id.in_(project_users))).all()
    form = ManageForm()
    if user['rank'] != 'Member':
        form.users.choices = [(user.id, f"{user.firstname} {user.lastname}") for user in non_project_users]
    update_prev_urls(f"/project/{pid}/users", f"Users", project['name'])
    return render_template('users/view_all.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           form=form, project=project, user=user)

@app.route('/project/<pid>/transfer_owner', methods=['POST'])
@login_required
def transfer_ownership(pid):
    form = TransferOwnership()
    if form.validate_on_submit():
        current_owner = db.session.query(Roles).filter(Roles.id == current_user.id, Roles.pid == pid).first()
        if current_owner.rank == "Owner":
            new_owner = db.session.query(Users).filter_by(username = form.new_owner.data).first()
            db.session.query(Roles).filter_by(id = new_owner.id).update({Roles.rank: "Owner"}, synchronize_session = False)
            db.session.query(Roles).filter_by(id = current_user.id).update({Roles.rank: form.new_rank.data}, synchronize_session = False)
            db.session.commit()
        return redirect(url_for('view_projects'))

@app.route('/project/<pid>/forms')
@login_required
def view_forms(pid):
    project=project_data(pid)
    user=user_data(current_user.id, pid)
    incomplete = evaluation_data_all(pid, status_type='incomplete')
    complete = evaluation_data_all(pid, status_type='complete')
    update_prev_urls(f"/project/{pid}/forms", f"Your Forms", project['name'])
    return render_template('/forms/view_all.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           project=project, user=user, incomplete=incomplete, complete=complete)

@app.route('/project/<pid>/task/<tid>/form/create/<eid>', methods=['GET', 'POST'])
@login_required
def create_form(pid, tid, eid):
    form = EvaluationForm()
    project = db.session.query(Projects).filter_by(pid=pid).first()
    evaluation = evaluation_data(pid, eid)
    if form.validate_on_submit():
        db.session.query(Evaluations).filter(Evaluations.eid == eid).update({
            Evaluations.status: 'SUBMITTED',
            Evaluations.comment: form.comment.data or None
        })
        db.session.commit()
        db.session.add(Questions(eid=eid, category='Communication', answer=form.question1.data))
        db.session.add(Questions(eid=eid, category='Feedback', answer=form.question2.data))
        db.session.add(Questions(eid=eid, category='Attendance', answer=form.question3.data))
        db.session.add(Questions(eid=eid, category='Responsibility', answer=form.question4.data))
        db.session.add(Questions(eid=eid, category='Performance', answer=form.question5.data))
        db.session.add(Questions(eid=eid, category='Efficiency', answer=form.question6.data))
        db.session.commit()
        return redirect(url_for('view_forms', pid=pid))
    return render_template('/forms/create.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           form=form, project=project, user=current_user, evaluation=evaluation)

@app.route('/project/<pid>/forms/manage')
@login_required
def manage_forms(pid):
    project=project_data(pid)
    user=user_data(current_user.id, pid)
    update_prev_urls(f"/project/{pid}/forms/manage", f"Manage Forms", project['name'])
    return render_template('/forms/manage.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           project=project, user=user)

@app.route('/project/<pid>/scores/')
@login_required
def view_scores(pid):
    project=project_data(pid)
    user=user_data(current_user.id, pid)
    update_prev_urls(f"/project/{pid}/scores/", f"View Scores", project['name'])
    return render_template('scores/view_all.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           project=project, user=user)

@app.route('/project/<pid>/score/<id>')
@login_required
def view_score(pid, id):
    project=project_data(pid)
    user=user_data(current_user.id, pid)
    tasks=task_stats_data(pid, id)
    user_score=scores_data(pid, id)
    group_score=scores_data(pid)
    update_prev_urls(f"/project/{pid}/score/{id}", f"Scores for {user_score['user']['firstname']} {user_score['user']['lastname']}", project['name'])
    return render_template('scores/view.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           project=project, user=user, tasks=tasks, user_score=user_score, group_score=group_score)

@app.route('/project/<pid>/scores/manage')
@login_required
def manage_scores(pid):
    project=project_data(pid)
    user=user_data(current_user.id, pid)
    users = db.session.query(Evaluations.id)\
        .join(Forms, Forms.fid == Evaluations.fid)\
        .join(Tasks, Tasks.tid == Forms.tid)\
        .filter(Tasks.pid == pid, Evaluations.status == 'SUBMITTED', Evaluations.disabled == False)\
        .group_by(Evaluations.id)\
        .having(sa.func.count(Evaluations.id) > 2).all()
    users = [id for id, in users]
    update_prev_urls(f"/project/{pid}/scores/manage", f"Manage Scores", project['name'])
    return render_template('scores/manage.html', prev_urls=session['urls'], msg_form=MessageForm(),
                           project=project, user=user, scores=[scores_data(pid, id, True) for id in users])

def project_data_all(id):
    projects = db.session.query(
        Projects.pid, Projects.name, Projects.description, Projects.color, Roles.rank)\
        .join(Roles, Roles.pid == Projects.pid)\
        .filter(Roles.id == id).all()
    return [{
        'pid': pid,
        'name': name,
        'description': description,
        'color': color,
        'rank': rank
    } for (pid, name, description, color, rank) in projects]

def project_data(pid, with_users=True):
    if with_users:
        (name, description, color) = db.session.query(
            Projects.name, Projects.description, Projects.color)\
            .filter(Projects.pid == pid).first()
        roles = db.session.query(
            Roles.rank, Users.id, Users.firstname, Users.lastname, Users.username, Users.email)\
            .join(Users, Users.id == Roles.id)\
            .filter(Roles.pid == pid).all()
        data = {
            'pid': int(pid),
            'name': name,
            'description': description,
            'color': color,
        }
        data['users'] = [{
            'id': int(id),
            'firstname': firstname,
            'lastname': lastname,
            'username': username,
            'email': email,
            'rank': rank,
        } for (rank, id, firstname, lastname, username, email) in roles]
        return data
    (name, description, color) = db.session.query(
        Projects.name, Projects.description, Projects.color)\
        .filter(Projects.pid == pid).first()
    return {
        'pid': int(pid),
        'name': name,
        'description': description,
        'color': color,
    }

def user_data(id, pid=None):
    if pid:
        user = db.session.query(
            Users.firstname, Users.lastname, Users.username, Users.email, Roles.rank)\
            .join(Roles, Roles.id == Users.id)\
            .filter(Users.id == id, Roles.pid == pid).first()
        if user is None: return None
        (firstname, lastname, username, email, rank) = user
        return {
            'id': int(id),
            'firstname': firstname,
            'lastname': lastname,
            'username': username,
            'email': email,
            'rank': rank
        }
    (firstname, lastname, username, email) = db.session.query(
        Users.firstname, Users.lastname, Users.username, Users.email)\
        .filter(Users.id == id).first()
    return {
        'id': int(id),
        'firstname': firstname,
        'lastname': lastname,
        'username': username,
        'email': email,
    }

def role_data(pid, id):
    (rid, rank) = db.session.query(Roles.rid, Roles.rank)\
        .filter(sa.and_(Roles.pid == pid, Roles.id == id)).first()
    return {
        'rid': rid,
        'rank': rank
    }

def check_if_late(pid=None, tid=None):
    if pid:
        db.session.query(Tasks)\
            .filter(Tasks.pid == pid, Tasks.completed == None, datetime.now() > Tasks.deadline)\
            .update({ Tasks.status: 'OVERDUE' })
        db.session.commit()
    if tid:
        db.session.query(Tasks)\
            .filter(Tasks.tid == tid, Tasks.completed == None, datetime.now() > Tasks.deadline)\
            .update({ Tasks.status: 'OVERDUE' })
        db.session.query(Subtasks)\
            .filter(Subtasks.tid == tid, Subtasks.completed == None, datetime.now() > Subtasks.deadline)\
            .update({ Subtasks.status: 'OVERDUE' })
        db.session.commit()

def get_days_until_due(deadline):
    days = (datetime.strptime(deadline, "%b %d, %Y") - datetime.now()).days
    if days == 1:
        return f"Due tomorrow"
    elif days == -1:
        return f"Due Yesterday"
    elif days < 0:
        return f"{abs(days)} days late"
    elif days > 0:
        return f"Due in {abs(days)} days"
    else:
        return f"Due today"

def get_days_since_completed(completed, status):
    days = (datetime.now() - datetime.strptime(completed, "%b %d, %Y")).days
    if days == 1:
        return f"{status} yesterday"
    elif days == 0:
        return f"{status} today"
    else:
        return f"{status} {days} days ago"

def task_data_all(pid, only_assigned_tasks=True, status_type='all', other_id=None, days_until_due=False):
    check_if_late(pid)
    task_filters = {
        'all': sa.and_(Tasks.pid == pid),
        'complete': sa.and_(Tasks.pid == pid, sa.not_(Tasks.completed == None)),
        'incomplete': sa.and_(Tasks.pid == pid, Tasks.completed == None),
    }
    if only_assigned_tasks:
        tasks = db.session.query(
            Tasks.tid, Tasks.name, Tasks.description, Tasks.status, Tasks.deadline, Tasks.completed)\
            .join(Assignments, Assignments.tid == Tasks.tid)\
            .filter(Assignments.id == (current_user.id if other_id is None else other_id), task_filters[status_type]).all()
    else:
        tasks = db.session.query(
            Tasks.tid, Tasks.name, Tasks.description, Tasks.status, Tasks.deadline, Tasks.completed)\
            .filter(task_filters[status_type]).all()
    return [{
        'tid': int(tid),
        'name': name,
        'description': description,
        'status': normalize(status),
        'deadline': fmtTime(deadline),
        'completed': None if completed is None else fmtTime(completed),
        'due': None if not days_until_due
            else get_days_since_completed(fmtTime(completed), normalize(status)) if completed is not None
            else get_days_until_due(fmtTime(deadline))
    } for (tid, name, description, status, deadline, completed) in tasks]

def task_data(pid, tid, with_extra_data=False):
    check_if_late(tid=tid)
    (name, description, status, deadline, completed) = db.session.query(
        Tasks.name, Tasks.description, Tasks.status, Tasks.deadline, Tasks.completed)\
        .filter(Tasks.tid == tid).first()
    data = {
        'tid': int(tid),
        'name': name,
        'description': description,
        'status': normalize(status),
        'deadline': fmtTime(deadline),
        'completed': None if completed is None else fmtTime(completed)
    }
    if not with_extra_data: return data
    data['subtasks'] = subtasks_data(tid)
    data['assignments'] = assignment_data(pid, tid)
    data['history'] = task_history(tid)
    return data

def subtasks_data(tid):
    subtasks = db.session.query(Subtasks.stid, Subtasks.name, Subtasks.status, Subtasks.description,
                                Subtasks.deadline, Subtasks.completed).filter(Subtasks.tid == tid).all()
    return [{
        'stid': int(stid),
        'name': name,
        'description': description,
        'status': normalize(status),
        'deadline': fmtTime(deadline),
        'completed': fmtTime(completed) if completed is not None else None,
        'due': get_days_since_completed(fmtTime(completed), normalize(status)) if completed is not None
                          else get_days_until_due(fmtTime(deadline))
    } for (stid, name, status, description, deadline, completed) in subtasks]

def assignment_data(pid, tid):
    assignments = db.session.query(
        Assignments.aid, Assignments.request,
        Users.id, Users.firstname, Users.lastname, Users.username, Users.email, Roles.rank)\
        .join(Users, Users.id == Assignments.id)\
        .join(Roles, Roles.id == Users.id)\
        .filter(Assignments.tid == tid, Roles.pid == pid).all()
    return [{
        'aid': aid,
        'request': request,
        'user': {
            'id': id,
            'firstname': firstname,
            'lastname': lastname,
            'username': username,
            'email': email,
            'rank': rank
        }
    } for (aid, request, id, firstname, lastname, username, email, rank) in assignments]

def task_history(tid):
    changes = db.session.query(Changes.time, Changes.action)\
        .filter(Changes.tid == tid).order_by(Changes.time).all()
    history = []
    for (time, action) in changes:
        change = {
            'time': fmtTime(time),
            'action': action,
        }
        history.append(change)
    return history

def subtask_data(stid):
    subtask = db.session.query(Subtasks.name, Subtasks.description,
                               Subtasks.status, Subtasks.deadline, Subtasks.completed).filter(Subtasks.stid == stid).first()
    (name, description, status, deadline, completed) = subtask
    return {
        'stid': stid,
        'name': name,
        'description': description,
        'status': status,
        'deadline': deadline,
        'completed': completed
    }

def evaluation_data_all(pid, only_assigned_forms=True, status_type='all', other_id=None):
    form_filters = {
        'all': sa.and_(Tasks.pid == pid),
        'complete': sa.and_(Tasks.pid == pid, Evaluations.status == 'SUBMITTED'),
        'incomplete': sa.and_(Tasks.pid == pid, Evaluations.status == 'NOT_SUBMITTED'),
    }
    if only_assigned_forms:
        evaluations = db.session.query(
            Evaluations.eid, Evaluations.disabled, Evaluations.status,
            Users.firstname, Users.lastname, Tasks.tid, Tasks.name, Tasks.status, Tasks.completed)\
            .join(Forms, Forms.fid == Evaluations.fid)\
            .join(Tasks, Tasks.tid == Forms.tid)\
            .join(Users, Users.id == Evaluations.id)\
            .filter(Forms.id == current_user.id, form_filters[status_type]).all()
    else:
        evaluations = db.session.query(
            Evaluations.eid, Evaluations.disabled, Evaluations.status,
            Users.firstname, Users.lastname, Tasks.tid, Tasks.name, Tasks.status, Tasks.completed)\
            .join(Forms, Forms.fid == Evaluations.fid)\
            .join(Tasks, Tasks.tid == Forms.tid)\
            .join(Users, Users.id == Evaluations.id)\
            .filter(form_filters[status_type]).all()
    return { 'forms': [{
        'eid': eid,
        'task': {
            'name': task_name,
            'status': normalize(task_status),
            'completed': fmtTime(task_completed),
            'tid': tid
        },
        'target': f"{firstname} {lastname}",
        'disabled': disabled,
        'status': capwords(status.replace('_', ' '))
    } for (eid, disabled, status, firstname, lastname, tid, task_name, task_status, task_completed) in evaluations]}

def evaluation_data(pid, eid, with_questions=False, with_user=False):
    (eid, disabled, status, comment, t_firstname, t_lastname, tid, t_name, t_status, t_completed, fid) = db.session.query(
        Evaluations.eid, Evaluations.disabled, Evaluations.status, Evaluations.comment,
        Users.firstname, Users.lastname, Tasks.tid, Tasks.name, Tasks.status, Tasks.completed, Forms.fid)\
        .join(Forms, Forms.fid == Evaluations.fid)\
        .join(Tasks, Tasks.tid == Forms.tid)\
        .join(Users, Users.id == Evaluations.id)\
        .filter(Tasks.pid == pid, Evaluations.eid == eid).first()
    data = {
        'eid': int(eid),
        'task': {
            'name': t_name, 'status': normalize(t_status), 'date': fmtTime(t_completed), 'tid': int(tid)
        },
        'target': f"{t_firstname} {t_lastname}",
        'disabled': disabled, 'comment': comment, 'status': normalize(status)
    }
    if with_questions:
        questions = db.session.query(Questions.category, Questions.answer).filter(Questions.eid == eid).all()
        data['questions'] = [{
            'category': category,
            'answer': int(answer)
        } for (category, answer) in questions]
    if with_user:
        (u_firstname, u_lastname) = db.session.query(Users.firstname, Users.lastname)\
            .join(Forms, Forms.id == Users.id)\
            .join(Evaluations, Evaluations.fid == Forms.fid)\
            .filter(Forms.fid == fid).first()
        data['user'] = f"{u_firstname} {u_lastname}"
    return data

def task_stats_data(pid, id):
    return {
        'all': db.session.query(sa.func.count(Tasks.tid))
            .join(Assignments, Assignments.tid == Tasks.tid)
            .filter(Assignments.id == id, Tasks.pid == pid).scalar(),
        'completed': db.session.query(sa.func.count(Tasks.tid))
            .join(Assignments, Assignments.tid == Tasks.tid)
            .filter(Assignments.id == id, Tasks.pid == pid, sa.or_(Tasks.status == 'COMPLETED', Tasks.status == 'COMPLETED_LATE')).scalar(),
        'skipped': db.session.query(sa.func.count(Tasks.tid))
            .join(Assignments, Assignments.tid == Tasks.tid)
            .filter(Assignments.id == id, Tasks.pid == pid, Tasks.status == 'SKIPPED').scalar(),
    }

def scores_data(pid, id=None, include_disabled=False):
    scores = { 'categories': {} }
    if id is not None:
        scores['user'] = user_data(id, pid)
        filter = sa.and_(Evaluations.id == id, Tasks.pid == pid, Evaluations.disabled == False)
    else:
        filter = sa.and_(Tasks.pid == pid, Evaluations.disabled == False)
    (count) = db.session.query(sa.func.count(Evaluations.eid))\
        .join(Forms, Forms.fid == Evaluations.fid)\
        .join(Tasks, Tasks.tid == Forms.tid)\
        .filter(filter).scalar()
    if (not count < 3):
        for category in categories:
            (score,) = db.session.query(
                sa.cast(sa.func.avg(Questions.answer).label('average'), sa.Numeric(10, 2)))\
                .join(Evaluations, Evaluations.eid == Questions.eid)\
                .join(Forms, Forms.fid == Evaluations.fid)\
                .join(Tasks, Tasks.tid == Forms.tid)\
                .filter(filter, Questions.category == category).first()
            scores['categories'][category] = score
        (score,) = db.session.query(
            sa.cast(sa.func.avg(Questions.answer).label('average'), sa.Numeric(10, 2)))\
            .join(Evaluations, Evaluations.eid == Questions.eid)\
            .join(Forms, Forms.fid == Evaluations.fid)\
            .join(Tasks, Tasks.tid == Forms.tid)\
            .filter(filter, Tasks.pid == pid).first()
        scores['overall'] = score
    return scores

@app.route('/projects/get')
@login_required
def get_project_data_all():
    return { 'projects': project_data_all(current_user.id) }

@app.route('/projects/get/<pid>')
@login_required
def get_project_data(pid):
    return { 'project': project_data(pid) }

@app.route('/projects/create', methods=['POST'])
@login_required
def create_project():
    form = ProjectForm()
    if form.validate_on_submit():
        name = form.name.data
        project = db.session.query(Projects).filter_by(name=name).first()
        if project is None:
            project = Projects(
                name=name,
                description=form.description.data,
                color=form.color.data)
            db.session.add(project)
            db.session.commit()
            db.session.add(Roles(rank="Owner", id=current_user.id, pid=project.pid))
            db.session.commit()
            return { 'code': 200, 'message': f"Successfully created {form.name.data}" }
        return { 'code': 400, 'message': f"A project with name {form.name.data} already exists" }

@app.route('/project/update/<pid>', methods=['POST'])
@login_required
def update_project(pid):
    form = ProjectForm()
    if form.validate_on_submit():
        project = db.session.query(Projects)\
            .filter(Projects.name == form.name.data, sa.not_(Projects.pid == pid)).first()
        if project is None:
            project = db.session.query(Projects)\
                .filter(Projects.pid == pid).first()
            db.session.query(Projects)\
                .filter(Projects.pid == pid)\
                .update({
                    Projects.name: form.name.data,
                    Projects.description: form.description.data,
                    Projects.color: form.color.data
                }, synchronize_session = False)
            db.session.commit()
            return { 'code': 200, 'message': f"Successfully updated {form.name.data}" }
        return { 'code': 400, 'message': f"A project with name {form.name.data} already exists" }

@app.route('/project/transfer/<pid>', methods=['POST'])
@login_required
def transfer_project(pid):
    form = TransferOwnership()
    users = [(user.id, f"{user.firstname} {user.lastname}") for user in db.session.query(Users.id, Users.firstname, Users.lastname)\
        .join(Roles, Roles.id == Users.id)\
        .filter(Roles.pid == pid, sa.not_(Users.id == current_user.id)).all()]
    form.new_owner.choices = users
    if form.validate_on_submit():
        current_owner = db.session.query(Roles).filter(Roles.id == current_user.id, Roles.pid == pid).first()
        if current_owner.rank != "Owner":
            return { 'code': 400, 'message': "You are not the project owner" }
        new_owner = db.session.query(Users).filter_by(id = form.new_owner.data).first()
        db.session.query(Roles)\
            .filter_by(pid = pid, id = new_owner.id)\
            .update({Roles.rank: "Owner"}, synchronize_session = False)
        db.session.query(Roles)\
            .filter_by(pid = pid, id = current_user.id)\
            .update({Roles.rank: form.new_rank.data}, synchronize_session = False)
        db.session.commit()
        return { 'code': 200, 'message': 'OK' }

@app.route('/projects/delete/<pid>')
@login_required
def delete_project(pid):
    (rank) = db.session.query(Roles.rank).filter(Roles.id == current_user.id, Roles.pid == pid).first()
    if rank[0] != "Owner": return redirect(url_for('view_projects'))
    db.session.query(Projects).filter(Projects.pid == pid).delete()
    db.session.commit()
    return redirect(url_for('view_projects'))

@app.route('/users/get/<id>')
def get_user(id):
    return { 'user': user_data(id) }

@app.route('/projects/<pid>/users/get')
def get_user_data_all(pid):
    users = db.session.query(Users.id).join(Roles, Roles.id == Users.id)\
        .filter(Roles.pid == pid).all()
    return { 'users': [user_data(user.id, pid) for user in users] }

@app.route('/projects/<pid>/users/get/<id>')
def get_user_data(pid, id):
    return { 'user': user_data(id, pid) }

@app.route('/project/<pid>/users/add', methods=['POST'])
@login_required
def add_user(pid):
    form = ManageForm()
    subquery = db.session.query(Roles.id).filter(Roles.pid == pid).subquery()
    non_project_users = db.session.query(Users)\
        .filter(sa.not_(Users.id.in_(subquery))).all()
    form.users.choices = [(user.id, f"{user.firstname} {user.lastname}") for user in non_project_users]
    if form.validate_on_submit():
        id = form.users.data
        target = db.session.query(Roles).filter_by(pid=pid, id=id).first()
        if target is not None:
            return { 'code': 400, 'message': 'User is already on the project' }
        user = db.session.query(Users).filter_by(id=id).first()
        if user is None:
            return { 'code': 400, 'message': 'User does not exist' }
        db.session.add(Roles(id=id, pid=pid, rank='Leader' if form.rank.data else 'Member'))
        db.session.commit()
    return { 'code': 200, 'message': user.id }

@app.route('/project/<pid>/users/remove/<id>', methods=['GET', 'POST'])
@login_required
def remove_user(pid, id):
    user = user_data(current_user.id, pid)
    target = user_data(id, pid)
    if (user['rank'] == 'Leader' and target['rank'] == 'Member') or user['rank'] == 'Owner':
        db.session.query(Roles).filter_by(pid=pid, id=id).delete(synchronize_session=False)
        tasks = db.session.query(Tasks.tid).filter(Tasks.pid == pid).subquery()
        db.session.query(Assignments)\
            .filter(Assignments.id == target['id'], Assignments.tid.in_(tasks)).delete(synchronize_session=False)
        db.session.query(Forms)\
            .filter(Forms.id == target['id'], Forms.tid.in_(tasks)).delete(synchronize_session=False)
        db.session.flush()
        forms = db.session.query(Forms.fid)\
            .join(Tasks, Tasks.tid == Forms.tid).filter(Tasks.pid == pid).subquery()
        db.session.query(Evaluations)\
            .filter(Evaluations.id == target['id'], Evaluations.fid.in_(forms)).delete(synchronize_session=False)
        db.session.commit()
        return { 'code': 200, 'message': f"Successfully removed user {target['firstname']} {target['lastname']} to the project" }
    return { 'code': 400, 'message': 'Insufficient permissions' }

@app.route('/projects/<pid>/tasks/get/<tid>')
def get_task_data(pid, tid):
    return task_data(pid, tid, with_extra_data=True)

@app.route('/projects/<pid>/tasks/get/assigned')
def get_assigned_task_data_all(pid):
    return { 'tasks' : task_data_all(pid) }

@app.route('/projects/<pid>/tasks/get/')
def get_task_data_all(pid):
    return { 'tasks' : task_data_all(pid, only_assigned_tasks=False, days_until_due=True) }

@app.route('/project/<pid>/tasks/create', methods=['GET', 'POST'])
@login_required
def create_task(pid):
    form = TaskForm()
    users = [(user.id, f"{user.firstname} {user.lastname}") for user in db.session.query(Users.id, Users.firstname, Users.lastname)\
        .join(Roles, Roles.id == Users.id)\
        .filter(Roles.pid == pid).all()]
    form.users.choices = users
    if form.validate_on_submit():
        if form.deadline.data < date.today():
            return { 'code': 400, 'message': "The deadline cannot be in the past" }
        task = Tasks(name=form.name.data, description=form.description.data, status="NOT_STARTED", deadline=form.deadline.data, pid=pid)
        db.session.add(task)
        db.session.commit()
        for user in form.users.data:
            assignment = Assignments(id=user, tid=task.tid)
            db.session.add(assignment)
            db.session.commit()
        return { 'code': 200, 'message': "Task added successfully" }

@app.route('/project/<pid>/tasks/<tid>/delete')
@login_required
def delete_task(pid, tid):
    (rank) = db.session.query(Roles.rank).filter(Roles.id == current_user.id, Roles.pid == pid).first()
    if rank[0] != "Member":
        db.session.query(Tasks).filter(Tasks.tid == tid).delete()
        db.session.commit()
    return redirect(url_for('manage_tasks', pid=pid))


@app.route('/projects/<pid>/tasks/<tid>/update', methods=['GET', 'POST'])
@login_required
def update_task(pid, tid):
    form = TaskForm()
    users = [(user.id, f"{user.firstname} {user.lastname}") for user in db.session.query(Users.id, Users.firstname, Users.lastname)\
        .join(Roles, Roles.id == Users.id)\
        .filter(Roles.pid == pid).all()]
    form.users.choices = users
    form.submit.label.text = 'Save Changes'
    if form.validate_on_submit():
        if len(form.users.data) == 0:
            return { 'code': 400, 'message': "Task needs at least 1 user assigned to it" }
        db.session.query(Tasks).filter(Tasks.tid == tid).update({
            Tasks.name: form.name.data,
            Tasks.description: form.description.data,
            Tasks.deadline: form.deadline.data
        })
        db.session.commit()
        assigned_users = [id for id, in db.session.query(Assignments.id).filter(Assignments.tid == tid).all()]
        for id in assigned_users:
            if id not in form.users.data:
                db.session.query(Assignments).filter(Assignments.id == id, Assignments.tid == tid).delete()
                db.session.commit()
        for id in form.users.data:
            if id not in assigned_users:
                db.session.add(Assignments(id=id, tid=tid, request=None))
                db.session.commit()
        return { 'code': 200, 'message': "Task updated successfully" }

def new_task_status(deadline, request):
    """Takes the task and request to change the task's status, and determines the new task status
        - Ex: Request is to skip the task -> "SKIPPED" is returned
        - Ex: Request is to submit the task and the task's deadline is in the past -> "COMPLETED LATE" is returned

    Args:
        task (dict): dictionary of task data
        request (string): Literal of 'start', 'skip', or 'submit', based on request to change task status

    Returns:
        string: The new status of the task
    """
    late = datetime.now() > fmtDate(deadline)
    if request == 'start':
        if late: return 'OVERDUE'
        return 'IN_PROGRESS'
    if request == 'submit':
        if late: return 'COMPLETED_LATE'
        return 'COMPLETED'
    return 'SKIPPED'

def change_task_status(pid, task, request, new_status):
    db.session.query(Tasks).filter(Tasks.tid == task['tid']).update({
        Tasks.status: new_status,
        Tasks.completed: date.today() if request != 'start' else None }, synchronize_session = False)
    db.session.commit()
    db.session.query(Assignments).filter(Assignments.tid == task['tid']).update({ Assignments.request: None }, synchronize_session = False)
    db.session.commit()
    if request == 'start': return
    assignments = assignment_data(pid, task['tid'])
    task_users = list(map(lambda assignment: assignment['user'], assignments))
    db.session.query(Subtasks).filter(Subtasks.tid == task['tid'], Subtasks.completed == None).update({
        Subtasks.status: 'SKIPPED',
        Subtasks.completed: datetime.now()
    })
    db.session.commit()
    for task_user in task_users:
        new_form = Forms(id=task_user['id'], tid=task['tid'])
        db.session.add(new_form)
        db.session.flush()
        new_evaluations = [Evaluations(fid=new_form.fid, id=target_user['id'])
                        for target_user in task_users if task_user['id'] != target_user['id']]
        db.session.add_all(new_evaluations)
        db.session.flush()
    db.session.commit()

@app.route('/projects/<pid>/tasks/<tid>/<request>/<action>', methods=["POST"])
@login_required
def update_assignment(pid, tid, request, action):
    task = task_data(pid, tid, with_extra_data=True)
    user = user_data(current_user.id, pid)
    (current_request, requests) = get_task_requests(task)
    if action == 'override':
        if user['rank'] == 'Member': return { 'code': 400, 'message': 'Insufficient permissions' }
        name = f"{user['firstname']} {user['lastname']}"
        new_change = f"{name} {fmtRequest[request.lower()]} this task by force"
        db.session.add(Changes(tid=tid, action=new_change, time=datetime.now()))
        change_task_status(pid, task, request, new_task_status(task['deadline'], request))
        return { 'code': 200, 'message': f"Task status overriden to {request} successfully" }
    if current_request is not None:
        if current_user.id in [assignment['user']['id'] for assignment in requests[current_request]]:
            return { 'code': 400, 'message': "You have already requested to change this task's status" }
    name = f"{current_user.firstname} {current_user.lastname}"
    new_change = f"{name} {fmtAction[action.lower()]} {request.lower()} this task"
    db.session.add(Changes(tid=tid, action=new_change, time=datetime.now()))
    db.session.commit()
    if action == 'deny':
        db.session.query(Assignments)\
            .filter(Assignments.tid == tid)\
            .update({ Assignments.request: None }, synchronize_session = False)
        db.session.commit()
        return { 'code': 200, 'message': 'Task denied successfully' }
    db.session.query(Assignments)\
        .filter(Assignments.tid == tid, Assignments.id == current_user.id)\
        .update({ Assignments.request: request.upper() }, synchronize_session = False)
    db.session.commit()
    unconfirmed_count = db.session.query(sa.func.count(Assignments.id))\
        .filter(Assignments.tid == tid, Assignments.request == None).scalar()
    if unconfirmed_count == 0:

        change_task_status(pid, task, request, new_task_status(task['deadline'], request))
    return { 'code': 200, 'message': f"User {current_user.id}'s request updated from {current_request} to {request}" }

@app.route('/project/<pid>/tasks/<tid>/subtasks/create', methods=['POST'])
@login_required
def create_subtask(pid, tid):
    form = SubtaskForm()
    if form.validate_on_submit():
        subtask = db.session.query(Subtasks)\
            .join(Tasks, Tasks.tid == Subtasks.tid)\
            .filter(Subtasks.name == form.name.data, Tasks.tid == tid).first()
        if subtask:
            return { 'code': 400, 'message': "A subtask with this name already exist for this task. Please choose a different name." }
        if form.deadline.data < date.today():
            return { 'code': 400, 'message': "The deadline cannot be in the past" }
        db.session.add(Subtasks(
            name=form.name.data,
            description=form.description.data,
            deadline=form.deadline.data, tid=tid))
        db.session.commit()
        new_change = f"{current_user.firstname} {current_user.lastname} created subtask {form.name.data}"
        db.session.add(Changes(tid=tid, action=new_change, time=datetime.now()))
        db.session.commit()
        return { 'code': 200, 'message': "Subtask Created Successfully" }

@app.route('/project/<pid>/tasks/<tid>/subtask/<stid>/<request>', methods=["POST"])
@login_required
def update_subtask(pid, tid, stid, request):
    user = user_data(current_user.id, pid)
    subtask = subtask_data(stid)
    action = f"{user['firstname']} {user['lastname']} {fmtRequest[request]} subtask {subtask['name']}"
    db.session.add(Changes(tid=tid, action=action, time=datetime.now()))
    db.session.commit()
    new_status = new_task_status(fmtTime(subtask['deadline']), request)
    db.session.query(Subtasks).filter(Subtasks.stid == stid).update({
        Subtasks.status: new_status,
        Subtasks.completed: date.today() if request != 'start' else None
    })
    db.session.commit()
    return { 'code': 200, 'message': 'Subtask status updated successfully' }

@app.route('/project/<pid>/subtask/get/<stid>', methods=['GET'])
@login_required
def get_subtask_data(pid, stid):
    return subtask_data(stid)

@app.route('/projects/<pid>/forms/get/')
def get_form_data_all(pid):
    return evaluation_data_all(pid, only_assigned_forms=False)

@app.route('/projects/<pid>/evaluations/get/<eid>')
def get_evaluation_data(pid, eid):
    return evaluation_data(pid, eid, with_questions=True, with_user=True)

@app.route('/projects/<pid>/evaluations/toggle/<eid>')
@login_required
def toggle_evaluation(pid, eid):
    evaluation = db.session.query(Evaluations).filter(Evaluations.eid == eid).first()
    evaluation.disabled = not evaluation.disabled
    db.session.commit()
    return { 'code': 200, 'message': 'Toggled form' }

@app.route('/messages/<id>', methods=['POST'])
@login_required
def message_user(id):
    form = MessageForm()
    if form.validate_on_submit():
        content = form.content.data
        subject = form.subject.data
        db.session.add(Messages(
            id=current_user.id, id2=id,
            subject=subject, content=content,
            date=date.today().strftime('%Y-%m-%d')
        ))
        db.session.commit()
        return { 'code': 200, 'message': 'Message sent' }
    return { 'code': 500, 'message': 'An error has occured' }

def message_data(id):
    data = {}
    messages = db.session.query(Messages, Users)\
        .join(Users, Users.id == Messages.id2)\
        .filter(Messages.id == id)\
        .order_by(Messages.date.desc()).all()
    data['sent'] = [{
        'mid': message.mid,
        'id': current_user.id,
        'user': f"{current_user.firstname} {current_user.lastname}",
        'id2': user.id,
        'target': f"{user.firstname} {user.lastname}",
        'subject': message.subject,
        'content': message.content, 'status': message.status, 'date': fmtTime(message.date)
    } for (message, user) in messages]
    messages = db.session.query(Messages, Users)\
        .join(Users, Users.id == Messages.id)\
        .filter(Messages.id2 == id)\
        .order_by(Messages.date.desc()).all()
    data['received'] = [{
        'mid': message.mid,
        'user': f"{user.firstname} {user.lastname}",
        'id': user.id,
        'target': f"{current_user.firstname} {current_user.lastname}",
        'id2': current_user.id,
        'subject': message.subject,
        'content': message.content, 'status': message.status, 'date': fmtTime(message.date)
    } for (message, user) in messages]
    return data

@app.route('/messages', methods=['GET'])
@login_required
def get_messages():
    return message_data(current_user.id)

@app.route('/messages/read/<mid>', methods=['GET'])
@login_required
def update_message(mid):
    db.session.query(Messages)\
        .filter(Messages.mid == mid)\
        .update({ Messages.status: 'READ' }, synchronize_session=False)
    db.session.commit()
    return { 'code': 200, 'message': 'Message has been read' }
