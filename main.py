import random
import time

import flask_wtf
from flask import Flask, render_template, request, redirect, url_for, flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship, declarative_base
from flask_ckeditor import CKEditor, CKEditorField
from flask_gravatar import Gravatar

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL, Email, EqualTo
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from datetime import datetime
import requests
import os
import send_funnc

# response = requests.get('https://api.npoint.io/c790b4d5cab58020d391')
# response.raise_for_status()
# all_post = response.json()
now = datetime.now()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(app)
Base = declarative_base()
ckeditor = CKEditor(app)
Bootstrap(app)
app.config['SECRET_KEY'] = 'yourfada'
login_manager = LoginManager(app)
gravatar = Gravatar(app,
                    size=40,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# creates a bidirectional users database(many to many)
class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    name = db.Column(db.String, nullable=False)
    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comments", back_populates="user")
    code = db.relationship("Code", back_populates="user")

class Code(db.Model):
    __tablename__ = "code"
    id = db.Column(db.Integer, primary_key=True)
    validity_time = db.Column(db.Float, nullable=False)
    forgot_code = db.Column(db.String, nullable=False)
    session_id = db.Column(db.Integer,nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = db.relationship("Users")

# creates a bidirectional blogpost database(many to many)
class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship("Users", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comment = db.relationship("Comments", back_populates="blog_post")


# creates a bidirectional users database(many to many)
class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment = db.Column(db.Text(1000), nullable=False)
    blog_post_id = db.Column(db.Integer, db.ForeignKey("blog_post.id"))
    user = db.relationship("Users", back_populates="comments")
    blog_post = db.relationship("BlogPost", back_populates="comment")


with app.app_context():
        db.create_all()


##WTForm
# form to create a post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField('Body')
    submit = SubmitField("Submit Post")

# forgot password form:
class Forgot(FlaskForm):
    email = StringField("enter your email", validators=[DataRequired(),Email()])
    submit = SubmitField("continue", id="submit2")

# code sent to user
class Forgot_code(FlaskForm):
    code = StringField("enter code", validators=[DataRequired()])
    submit = SubmitField("continue", id="submit2")

class New_Pass(FlaskForm):
    password = StringField("password",
                           validators=[DataRequired(), EqualTo("confirm_password", "passwords does not match")])
    confirm_password = StringField("confirm password", validators=[DataRequired()])
    submit = SubmitField("Set password")

# form to login
class LoginForm(FlaskForm):
    email = StringField("email", validators=[DataRequired(), Email()])
    password = StringField("password")
    style = {
        "class": "w-100 btn btn-lg btn-primary"
    }
    submit = SubmitField("login", id="submit2")


# form to register
class Register(FlaskForm):
    name = StringField("name", validators=[DataRequired()])
    email = StringField("email", validators=[DataRequired(), Email()])
    password = StringField("password",
                           validators=[DataRequired(), EqualTo("confirm_password", "passwords does not match")])
    confirm_password = StringField("confirm password", validators=[DataRequired()])
    sign_up = SubmitField("sign in", id="submit2")


# form to create a comment
class BlogComment(FlaskForm):
    comment = CKEditorField(validators=[DataRequired()])
    submit = SubmitField("comment", id="submit2")


# load user callback for the flask_login
@login_manager.user_loader
def load_user(user_id):
    return db.session.query(Users).get(user_id)


# checks if current user is the admin
def admin(current_user):
    if current_user.is_authenticated:
        if db.session.query(Users).filter_by(email=current_user.email).first().id == 1:
            return True
    else:
        return False


# app routes
@app.route('/')
def home():
    # checks if the user is an admin
    ADMIN = admin(current_user)
    all_post = db.session.query(BlogPost).all()
    return render_template("index.html", post=all_post, logged_in=current_user.is_authenticated, admin=ADMIN)


@app.route('/login', methods=['POST', 'GET'])
def login():
    now = datetime.now()
    login_form = LoginForm()
    # algorithm to log in a user
    if login_form.validate_on_submit():
        user = db.session.query(Users).filter_by(email=login_form.email.data).first()
        if user == None:
            flash("There's no account registered with that email", category="login")
            flash("click here to sign up instead", category="login")
            return redirect(url_for('login'))
        if check_password_hash(pwhash=user.password, password=login_form.password.data):
            login_user(user)
            return redirect(url_for("home"))
        else:
            flash("incorrect password", category="login")
            redirect(url_for('login'))

    messages = get_flashed_messages(with_categories=True)
    lent = len(messages)
    return render_template("login.html", form=login_form, now=now, len=lent, session_id=random.randint(10000,99999))


@app.route('/blogpost/<int:id>', methods=["POST", "GET"])
def blog_post(id):
    ADMIN = admin(current_user)
    # loads the clicked post from the database
    clicked = db.session.query(BlogPost)
    clicked = clicked.get(id)
    blog_post = clicked
    comment_form = BlogComment()
    # validates the comment
    if comment_form.validate_on_submit():
        # checks if the user is logged in else take them to the login page if they are not if they try to comment
        if current_user.is_authenticated:
            text = comment_form.comment.data
            new_comment = Comments(comment=text, blog_post=blog_post, user=current_user)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("blog_post", id=id))
        else:
            flash(message="you'll need to login first ", category='login')
            return redirect(url_for("login"))
    # fetches the post from the database
    post_ = db.session.query(BlogPost).get(id)
    # checks if the user wants to see all the post
    see_more = request.args.get("all")
    if see_more == "True":
        all_comment = True
        post_comment = post_.comment[::-1]
    elif len(post_.comment) < 1:
        all_comment = False
        post_comment = ["no comment"]
    else:
        all_comment = False
        post_comment = post_.comment[:5][::-1]


    return render_template('post.html', clicked_post=clicked, logged_in=current_user.is_authenticated,
                           admin=ADMIN, comment=comment_form, post_comment=post_comment, id=id, all_comment=all_comment
                           ,len_comment = len(post_.comment))


@app.route('/about')
def about():
    return render_template('about.html', logged_in=current_user.is_authenticated)


@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    # for a client to contact us
    if request.method == 'POST':
        name = request.form['name']
        mail = request.form['email']
        phone_no = request.form['phone']
        message = f"name:{name}\nsender email:{mail}\n Phone no:{phone_no}" + request.form['message']
        # sends the message
        send_funnc.send(mail='mohudemypython@gmail.com', password=os.environ.get('password'),
                        receive_addrs='mohammedoyawoye@gmail.com', message=message)
        send_funnc.send(mail='mohudemypython@gmail.com', password=os.environ.get('password'),
                        receive_addrs=mail, message="your message has been sent to us, we'll get in touch soon")
        return render_template('contact.html', message="message sent successfully")
    else:
        return render_template('contact.html', message='contact me')


@app.route("/make_post", methods=["GET", "POST"])
@login_required
def make_post():
    ADMIN = admin(current_user)
    from datetime import datetime
    now = datetime.now()
    create_post_form = CreatePostForm()
    if ADMIN:
        if create_post_form.validate_on_submit():
            title = create_post_form.title.data
            subtitle = create_post_form.subtitle.data
            body = create_post_form.body.data
            date = now.strftime("%B %m, %Y")
            img_url = create_post_form.img_url.data
            with app.app_context():
                new_post = BlogPost(title=title, subtitle=subtitle, author=current_user, body=body, date=date,
                                    img_url=img_url)
                db.session.add(new_post)
                db.session.commit()
                return "posted successfully"
    else:
        return "unauthorized"
    if ADMIN:
        return render_template("make-post.html", form=create_post_form, act="New Post")
    else:
        return "unauthorized"


@app.route('/edit_post/<int:id>', methods=["Get", "POST"])
@login_required
def edit_post(id):
    ADMIN = admin(current_user)
    if ADMIN:
        with app.app_context():
            clicked_post = db.session.query(BlogPost).get(id)
            create_post_form = CreatePostForm(title=clicked_post.title,
                                              subtitle=clicked_post.subtitle,
                                              body=clicked_post.body,
                                              author=clicked_post.user_id.name,
                                              img_url=clicked_post.img_url)
            if create_post_form.validate_on_submit():
                title = create_post_form.title.data
                subtitle = create_post_form.subtitle.data
                body = create_post_form.body.data
                author = create_post_form.author.data
                img_url = create_post_form.img_url.data
                clicked_post.title = title
                clicked_post.subtitle = subtitle
                clicked_post.body = body
                clicked_post.author = author
                clicked_post.img_url = img_url
                db.session.commit()
                return redirect(url_for('blog_post', id=clicked_post.id))
    else:
        return "unauthorized"


    if ADMIN:
        return render_template("make-post.html", act="Edit Post", form=create_post_form)
    else:
        return 'unauthorized'


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    ADMIN = admin(current_user)
    if ADMIN:
        with app.app_context():
            deleted_post = db.session.query(BlogPost).get(id)
            db.session.delete(deleted_post)
            db.session.commit()
        return redirect(url_for("home"))
    else:
        return "unauthorized"


@app.route('/register', methods=['POST', 'GET'])
def register():
    now = datetime.now()
    register_form = Register()
    if register_form.validate_on_submit():
        new_user = Users(email=register_form.email.data,
                         name=register_form.name.data,
                         password=generate_password_hash(password=register_form.password.data,
                                                         method="pbkdf2:sha256",
                                                         salt_length=8),
                         )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))

    return render_template("register.html", form=register_form, now=now.year)


@app.route('/logout')
def log_out():
    logout_user()
    return redirect(url_for("home"))

@app.route("/forgot/password/<int:session_id>", methods=["GET","POST"])
def forgot_password(session_id):
    messages = get_flashed_messages(with_categories=True)
    lent = len(messages)
    from random_password_generator import generate_password
    new_pass_form = New_Pass()
    forgotform=Forgot()
    code_form = Forgot_code()
    if new_pass_form.validate_on_submit():
        user_code = db.session.query(Code).filter_by(session_id = session_id).first()
        user_code.user.password = generate_password_hash(password=new_pass_form.password.data, method="pbkdf2:sha256", salt_length=8)
        db.session.delete(user_code)
        db.session.commit()

        return f"password changed successfully <a href={url_for('login')}>click here to go to the login page</a>"


    if code_form.validate_on_submit():
        forgot_key = db.session.query(Code).filter_by(session_id=session_id).first().forgot_code
        if check_password_hash(forgot_key,code_form.code.data):
            return render_template("forgot_password.html", form=new_pass_form,now=now.year,len=lent)


    if forgotform.validate_on_submit():
        forgot_key = generate_password(8, 4, 4)
        user = db.session.query(Users).filter_by(email=forgotform.email.data).first()
        if user != None:
            message = f"Subject: bloggerblogger forgot password\n your confirmation code:{forgot_key}"
            send_funnc.send(mail='mohudemypython@gmail.com', password=os.environ.get('password'),
                        receive_addrs=user.email, message=message)
            newcode = Code(validity_time = time.time() + 180, forgot_code=generate_password_hash(password=forgot_key,salt_length=8), user=user, session_id=session_id)
            db.session.add(newcode)
            db.session.commit()
            return render_template("forgot_password.html", form=code_form, now=now.year,len=lent)



    return render_template("forgot_password.html", form=forgotform, now=now.year, len=lent)





if __name__ == "__main__":
    app.run(debug=True)
