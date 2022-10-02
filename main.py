from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_ckeditor import CKEditor, CKEditorField
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import datetime
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_gravatar import Gravatar
import os

Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "8BYkEfBA6O6donzWlSihBXox7C0sKR6b")
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///posts.db")
app.config['SQLALCHEMY_BINDS'] = {"users": os.environ.get("HEROKU_POSTGRESQL_AMBER_URL", "sqlite:///users.db"),
                                  "comments": os.environ.get("HEROKU_POSTGRESQL_AQUA_URL", "sqlite:///comments.db")}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CONFIGURE TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    __bind_key__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")
db.create_all()

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    # author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
db.create_all()

class Comment(db.Model):
    __tablename__ = "comments"
    __bind_key__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    # ***************Child Relationship*************#
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)

db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:index>", methods=["POST", "GET"])
def show_post(index):
    requested_post = BlogPost.query.get(index)
    comment_form = CommentForm()
    requested_post = BlogPost.query.filter_by(id=index).first()
    if request.method == "POST":
        if current_user.is_authenticated:
            new_comment = Comment(
                author_id=current_user.id,
                post_id=requested_post.id,
                text=request.form.get("body")
            )
            db.session.add(new_comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, form=comment_form)
        else:
            flash("Hmmm, could you put aside your asininity and log in first?")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def new():
    if request.method == "POST":
        title = request.form.get("title")
        subtitle = request.form.get("subtitle")
        img_url = request.form.get("img_url")
        body = request.form.get("body")
        date = datetime.datetime.now().strftime("%B %d, %Y")
        post = BlogPost(
            title=title,
            subtitle=subtitle,
            img_url=img_url,
            author_id=current_user.id,
            body=body,
            date=date,
        )
        db.session.add(post)
        db.session.commit()
        return redirect("/")

    else:
        form = CreatePostForm()
        return render_template("make-post.html", form=form)


@app.route("/edit_post/<post_id>", methods=["GET", "POST"])
@admin_only
def edit(post_id):
    post = BlogPost().query.filter_by(id=post_id).first()
    if request.method == "POST":
        post.title = request.form.get("title")
        post.subtitle = request.form.get("subtitle")
        post.img_url = request.form.get("img_url")
        post.body = request.form.get("body")
        post.date = datetime.datetime.now().strftime("%B %d, %Y")

        db.session.commit()

        return redirect("/")

    form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author_id=current_user.id,
        body=post.body
    )
    return render_template("make-post.html", form=form, edit=True)


@app.route("/delete/<post_id>", methods=["GET", "DELETE"])
@admin_only
def delete(post_id):
    post = BlogPost.query.filter_by(id=post_id).first()
    db.session.delete(post)
    db.session.commit()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if not current_user.is_authenticated:
        all_users = db.session.query(User).all()
        all_names = [user.name for user in all_users]
        all_emails = [user.email for user in all_users]
        if request.method == "POST":
            exists = False
            request_name = request.form.get("name")
            request_email = request.form.get("email")
            for name in all_names:
                if request_name == name:
                    exists = True
            for email in all_emails:
                if request_email == email:
                    exists = True
            if not exists:
                new_user = User(
                    email=request.form.get('email'),
                    password=generate_password_hash(request.form.get('password'),
                                                    method='pbkdf2:sha256',
                                                    salt_length=8),
                    name=request.form.get('name')
                )

                db.session.add(new_user)
                db.session.commit()

                login_user(new_user)

                return redirect(url_for("get_all_posts"))
            else:
                flash("Hmmm, seems like there is already one with this name or email)")
                return redirect(url_for("login"))
        else:
            return render_template("register.html", form=register_form)
    else:
        # flash("You are already authenticated, why do you even need that page?")
        return redirect(url_for("get_all_posts"))


@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if not current_user.is_authenticated:
        if request.method == "POST":
            user = User.query.filter_by(email=request.form.get("email")).first()
            if user:
                if check_password_hash(password=request.form.get("password"), pwhash=user.password):
                    login_user(user)
                    return redirect(url_for("get_all_posts"))
                else:
                    flash("Hmmm, seems like you are not the legitimate owner of the account, who'd know the password) Give it another shot nigga")
                    return render_template("login.html", form=login_form)
            else:
                flash("Hmmm, seems the email doesn't exist or was inadvertently deleted from the Database) Give it another shot nigga")
                return render_template("login.html", form=login_form)

        return render_template("login.html", form=login_form)
    else:
        # flash("You are already authenticated, why do you even need that page?")
        return redirect(url_for("get_all_posts"))


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
