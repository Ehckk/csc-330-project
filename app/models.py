from app import db, login
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Define the DB Schema
class Users(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password = db.Column(db.String(256), unique=False, nullable=False)
    firstname = db.Column(db.String(32), unique=False, nullable=False)
    lastname = db.Column(db.String(32), unique=False, nullable=False)
    email = db.Column(db.String(64), unique=True, nullable=False)
    roles = db.relationship('Roles', lazy=True, backref=db.backref('user', lazy='joined', passive_deletes=True))
    assignments = db.relationship('Assignments', lazy=True, backref=db.backref('user', lazy='joined', passive_deletes=True))
    forms = db.relationship('Forms', lazy=True, backref=db.backref('user', lazy='joined', passive_deletes=True))
    evaluations = db.relationship('Evaluations', lazy=True, backref=db.backref('user', lazy='joined', passive_deletes=True))

    def set_password(self, password):
        # Store hashed (encrypted) password in database
        self.password = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password, password)
    def __repr__(self):
        return f"<Users id={self.id}, username={self.username}, firstname={self.firstname}, lastname={self.lastname}, email={self.email}>"

class Projects(db.Model):
    __tablename__ = 'projects'
    pid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.Text, unique=False, nullable=False)
    color = db.Column(db.Enum('red', 'blaze', 'orange', 'dandelion', 'yellow', 'chartreuse',
    'green', 'emerald', 'teal', 'turquiose', 'skyblue', 'blue',
    'deepblue', 'indigo', 'purple', 'fuschia', 'magenta', 'rose'), unique=False, nullable=False)
    roles = db.relationship('Roles', lazy=True, backref=db.backref('project', lazy='joined', passive_deletes=True))
    tasks = db.relationship('Tasks', lazy=True, backref=db.backref('project', lazy='joined', passive_deletes=True))

    def __repr__(self):
        return f"<Projects pid={self.pid}, name={self.name}, description={self.description}, color={self.color}>"

class Roles(db.Model):
    __tablename__ = 'roles'
    rid = db.Column(db.Integer, primary_key=True)
    rank = db.Column(db.Enum('Member', 'Leader', 'Owner'), nullable=False)
    id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='cascade'))
    pid = db.Column(db.Integer, db.ForeignKey('projects.pid', ondelete='cascade'))

    def __repr__(self):
        return f"<Roles rid={self.rid}, rank={self.rank}, id={self.id}, pid={self.pid}>"

class Tasks(db.Model):
    __tablename__= 'tasks'
    tid = db.Column(db.Integer, primary_key=True)
    pid = db.Column(db.Integer, db.ForeignKey('projects.pid', ondelete='cascade'))
    name = db.Column(db.String(64), unique=False, nullable=False)
    description = db.Column(db.Text, unique=False, nullable=False)
    status = db.Column(db.Enum('NOT_STARTED', 'IN_PROGRESS', 'OVERDUE', 'COMPLETED', 'COMPLETED_LATE', 'SKIPPED'), nullable=False)
    deadline = db.Column(db.DATE, nullable=False)
    completed = db.Column(db.DATE, nullable=True)
    assignments = db.relationship('Assignments', lazy=True, backref=db.backref('task', lazy='joined', passive_deletes=True))
    subtasks = db.relationship('Subtasks', lazy=True, backref=db.backref('task', lazy='joined', passive_deletes=True))
    forms = db.relationship('Forms', lazy=True, backref=db.backref('task', lazy='joined', passive_deletes=True))
    changes = db.relationship('Changes', lazy=True, backref=db.backref('task', lazy='joined', passive_deletes=True))

    def __repr__(self):
        return f"<Tasks tid={self.tid}, name={self.name}, description={self.description}, status={self.status}, deadline={self.deadline}, completed={self.completed}, pid={self.pid}>"

class Subtasks(db.Model):
    __tablename__= 'subtasks'
    stid = db.Column(db.Integer, primary_key=True)
    tid = db.Column(db.Integer, db.ForeignKey('tasks.tid', ondelete='cascade'))
    name = db.Column(db.String(64), unique=False, nullable=False)
    description = db.Column(db.Text, unique=False, nullable=False)
    status = db.Column(db.Enum('NOT_STARTED', 'IN_PROGRESS', 'OVERDUE', 'COMPLETED', 'COMPLETED_LATE', 'SKIPPED'), nullable=False, default='NOT_STARTED')
    deadline = db.Column(db.DATE, nullable=True)
    completed = db.Column(db.DATE, nullable=True)

    def __repr__(self):
        return f"<Subtasks stid={self.stid}, name={self.name}, description={self.description}, status={self.status}, deadline={self.deadline}, completed={self.completed}, tid={self.tid}>"

class Assignments(db.Model):
    __tablename__ = 'assignments'
    aid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='cascade'))
    tid = db.Column(db.Integer, db.ForeignKey('tasks.tid', ondelete='cascade'))
    request = db.Column(db.Enum('START', 'SUBMIT', 'SKIP'), nullable=True)

    def __repr__(self):
        return f"<Assignment aid={self.aid}, request={self.request}, id={self.id}, tid={self.tid}>"

class Changes(db.Model):
    __tablename__ = 'changes'
    cid = db.Column(db.Integer, primary_key=True)
    tid = db.Column(db.Integer, db.ForeignKey('tasks.tid', ondelete='cascade'))
    action = db.Column(db.Text, nullable=False)
    time = db.Column(db.DATETIME, nullable=False)

    def __repr__(self):
        return f"<Changes cid={self.cid}, action={self.action}, time={self.time}, tid={self.tid}>"

class Forms(db.Model):
    __tablename__= 'forms'
    fid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='cascade'))
    tid = db.Column(db.Integer, db.ForeignKey('tasks.tid', ondelete='cascade'))
    evaluations = db.relationship('Evaluations', lazy=True, backref=db.backref('form', lazy='joined', passive_deletes=True))

    def __repr__(self):
        return f"<Forms fid={self.fid}, id={self.id}, tid={self.tid}>"

class Evaluations(db.Model):
    __tablename__= 'evaluations'
    eid = db.Column(db.Integer, primary_key=True)
    fid = db.Column(db.Integer, db.ForeignKey('forms.fid', ondelete='cascade'))
    id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='cascade'))
    status = db.Column(db.Enum('NOT_SUBMITTED', 'SUBMITTED'), nullable=False, default='NOT_SUBMITTED')
    comment = db.Column(db.Text, unique=False, nullable=True)
    disabled = db.Column(db.Boolean, unique=False, default=False)
    questions = db.relationship('Questions', lazy=True, backref=db.backref('evaluation', lazy='joined', passive_deletes=True))

    def __repr__(self):
        return f"<Evaluations eid={self.eid}, status={self.status}, comment={self.comment}, disabled={self.disabled} fid={self.fid}, id={self.id}>"

class Questions(db.Model):
    __tablename__= 'questions'
    qid = db.Column(db.Integer, primary_key=True)
    eid = db.Column(db.Integer, db.ForeignKey('evaluations.eid', ondelete='cascade'))
    category = db.Column(db.Enum('Communication', 'Feedback', 'Attendance', 'Responsibility', 'Performance', 'Efficiency'), nullable=False)
    answer = db.Column(db.Integer, unique=False, nullable=True)

    def __repr__(self):
        return f"<Questions={self.qid}, category={self.category}, answer={self.answer} eid={self.eid}>"

class Messages(db.Model):
    __tablename__ = 'messages'
    mid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='cascade'))
    id2 = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='cascade'))
    subject = db.Column(db.Text, unique=False, nullable=False)
    content = db.Column(db.Text, unique=False, nullable=False)
    status = db.Column(db.Enum('READ', 'UNREAD'), nullable=False, default='UNREAD')
    date = db.Column(db.DATE, nullable=False)

    def __repr__(self):
        return f"<Messages={self.mid}, subject={self.subject} content={self.content} status={self.status} date={self.date} id={self.id} id2={self.id2}>"

# load_user is a function that's used by flask_login to manage the session.
# It simply returns the object associated with the authenticated user.

@login.user_loader
def load_user(id):
    return db.session.query(Users).get(int(id))

