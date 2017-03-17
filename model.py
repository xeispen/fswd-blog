from google.appengine.ext import db
from helper import *


# datastore class for users
class User(db.Model):
    """User datastore class and related functions

    Everytime a new user is created, the user name, password hash
    and optional email are stored in an instance of this class
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # class methods for User
    @classmethod
    def by_id(cls, uid):
        """ Returns the user instance by id """
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        """Looks through all User datastore objects and returns the instance
        that matches name

        Args:
            user name
        Returns:
            User instance matching name
        """
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        """Creates a new User instance with args but does not store it

        Args:
            name: user name
            pw: password
            email: user email
        Returns:
            User instance with hashed name and pw
        """
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, name, pw):
        """Checks if the name and pw in the args are valid
        Args:
            name: user name
            pw: password
        Returns:
            User instance if the args are valid
        """
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# datastore class for posts
class Post(db.Model):
    """Post datastore class and related functions

    Everytime a new post is created, an instance of this class
    is created
    """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    liked_by = db.ListProperty(int, default=[])
    likes = db.IntegerProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by = db.ReferenceProperty(User, collection_name='user_posts')

    def render(self, uid):
        """Retrieves and renders individual posts and comments"""
        # adds html line breaks
        self._render_text = self.content.replace('\n', '<br>')
        # adds the user name to be used for rendering
        self._name = self.created_by.name
        # finds the comments of the post
        comments = Comments.return_comments(self.key().id())
        # creates a dictionaty of post and comments for rendering
        params = dict(p=self, comments=comments, uid=uid)
        return render_str("post.html", **params)

    def check_if_liked(self, usr):
        """ Checks if a post instance was liked by usr """
        return usr in self.liked_by

    def increment(self, usr):
        """Increments the like counter on the post instance"""
        self.likes += 1
        self.liked_by.append(usr)
        self.put()

    def decrease(self, usr):
        """Decreases the like counter on the post instance"""
        self.likes -= 1
        self.liked_by.remove(usr)
        self.put()

    def poster_id(self):
        """Returns user id of the blog post"""
        user = Post.created_by.get_value_for_datastore(self)
        return user.id()

    def poster(self):
        """Returns User instance of the blog post"""
        user = Post.created_by.get_value_for_datastore(self)
        return user


# datastore class for comments
class Comments(db.Model):
    """Comment datastore class and related functions

    Everytime a new comment is created, an instance of this class
    is created
    """
    comment = db.TextProperty(required=True)
    user = db.IntegerProperty(required=True)
    post = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self, user):
        """Retrieves and renders individual comments"""
        self._render_text = self.comment.replace('\n', '<br>')
        user_inst = User.by_id(self.user)
        self.id = self.user
        self._user = user_inst.name
        # creates a dictionaty of post and comments for rendering
        params = dict(c=self, uid=user)
        return render_str("comment.html", **params)

    @classmethod
    def return_comments(cls, pid):
        """Retrieves all instances of comments belonging to pid"""
        comments = cls.all().filter('post =', pid).order('created')
        return comments
