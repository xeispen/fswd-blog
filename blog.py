import os
import jinja2
import webapp2
import hmac
import hashlib
import string
import random
import re

import jinja2
import webapp2

from google.appengine.ext import db

#current directory + templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
#instantiate jinja environment
#Jinja will look for these templates in this directory
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

#hashing functions
SECRET = 'imsosecret'

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

#password hashing
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()
    #return hashlib.md5(s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


#####blog related

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

#in case we have user groups in future
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

#datastore object for user

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    #I can call this method on this object, not an instance
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        #u = db.GqlQuery("SELECT * FROM User WHERE name = %s" % name)
        #.get() returns first instance
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        #creates a password hash
        pw_hash = make_pw_hash(name, pw)
        #creates a new user object, but does not store it yet
        return cls(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        #makes sure username is returned and pw is valid
        if u and valid_pw(name, pw, u.pw_hash):
            return u


#datastore object for posts
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    likes = db.IntegerProperty(required = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    created_by = db.ReferenceProperty(User, collection_name = 'user_posts')

    def render(self):
        #adds html line breaks
        self._render_text = self.content.replace('\n', '<br>')
        #This does not seem to be working correctly
        comments = Comments.return_comments(self.key().id())
        self.comments = comments
        #test git
        return render_str("post.html", p = self)

    def increment(self):
        prev_like = self.likes
        curr_like = prev_like + 1
        self.likes = curr_like
        self.put()


    def decrease(self):
        prev_like = self.likes
        curr_like = prev_like - 1
        self.likes = curr_like
        self.put()


    #returns the user id of the blog post
    def poster_id(self):
        user = Post.created_by.get_value_for_datastore(self)
        return user.id()

    #returns the instance of the user
    def poster(self):
        user = Post.created_by.get_value_for_datastore(self)
        return user

#datastore object for comments
class Comments(db.Model):
    comment = db.TextProperty(required = True)
    user = db.IntegerProperty(required = True)
    post = db.IntegerProperty(required = True)

    def render(self):
        #adds html line breaks
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("comment.html", comment = self)

    @classmethod
    def return_comments(cls, pid):
        comments = cls.all().filter('post =', pid)
        return comments

#datastore object for likes
class Likes(db.Model):
    post = db.IntegerProperty(required = True)
    user = db.IntegerProperty(required = True)

    @classmethod
    def check_if_liked(cls, pid, uid):
        check = cls.all().filter('post =', pid).filter('user =', uid).get()
        return check



#class BlogHandler inherits from webapp2.RequestHandler
class BlogHandler(webapp2.RequestHandler):
    #eliminates need to retype self.response.out
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    #returns string of rendered template
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    #calls write and render_str
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    #function takes in name and val of cookie and sets it
    def set_secure_cookie(self, name, val):
        #convert val from unicode to str
        cookie_val = make_secure_val(str(val))
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    #function reads a cookie and returns the cookie + hash
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    #function sets the cookie
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    #checks if user is logged in or not
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        #sets local var user to uid and checks that this user exists
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


#handler for main blog URL
class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        #posts = db.GqlQuery("SELECT * FROM Post ORDER BY created desc LIMIT 10")
        #ancestor query
        posts.ancestor(blog_key())
        self.render("front.html", posts = posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        #make a key, find the post with post_id from url, whose parent is blog_key
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        #look up particular post
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)


class AddComment(PostPage):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        #look up particular post
        post = db.get(key)
        self.render("permalink.html", post = post)

    def post(self, post_id):
        comment = self.request.get('comment')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        #returns the user id
        uid = self.read_secure_cookie('user_id')
        c = Comments(comment = comment, user = int(uid), post = int(post_id))
        c.put()
        self.render("permalink.html", post = post)


#page displaying each user's own blog posts
class MyBlog(BlogHandler):
    def get(self):
        posts = self.user.user_posts
        #ancestor query
        posts.ancestor(blog_key())
        self.render("front.html", posts = posts)





class NewPost(BlogHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, likes = 0, created_by = self.user)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject = subject, content = content, error = error)



class DeletePost(BlogHandler):
    def get(self, post_id):
        #make a key, find the post with post_id from url, whose parent is blog_key
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        #returns the user id
        uid = self.read_secure_cookie('user_id')
        #returns the user id of the post
        puid = post.poster_id()

        if int(uid) == puid:
            post.delete()
            return self.redirect('/blog/myblog')
        else:
            self.write("You didn't post that!!!")


class EditPost(BlogHandler):

    def get(self, post_id):
        #make a key, find the post with post_id from url, whose parent is blog_key
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        #returns the user id
        uid = self.read_secure_cookie('user_id')
        #returns the user id of the post
        puid = post.poster_id()

        if int(uid) == puid:
            self.render('editpost.html', subject = post.subject, content = post.content)
        else:
            self.write("You didn't post that!!!")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject = subject, content = content, error = error)



class LikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        uid = self.read_secure_cookie('user_id')
        puid = post.poster_id()
        check = Likes.check_if_liked(int(post_id), int(uid))

        if int(uid) != puid:
            if check is None:
                like = Likes(post = int(post_id), user = int(uid))
                like.put()
                #increments counter on Post instance
                post.increment()
                self.redirect('/blog')
            else:
                self.write("You can only like each post once")

        else:
            self.write("You can't like your own post!!!")



class UnlikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        uid = self.read_secure_cookie('user_id')
        puid = post.poster_id()
        check = Likes.check_if_liked(int(post_id), int(uid))

        if int(uid) != puid:
            if check is None:
                self.write("You can only unlike a post if you have already liked it")
            else:
                check.delete()
                #decreases counter on Post instance
                post.decrease()
                self.redirect('/blog')
        else:
            self.write("You can't unlike your own post!!!")



class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)

#a-z, 0-9, between 3 and 20 characters
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

#any characters between 3 and 20
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

#checks that no email is supplied or email is valid
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        #fetch parameters from request
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        #params sent back to rendering
        #always send back username and email
        params = dict(username = self.username,
                      email = self.email)

        #if there are issues, errors are added into params
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        #if have_error is true, send back signup-form with params
        if have_error:
            self.render('signup-form.html', **params)
        #places username in url accessible by GET
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        #checks if user already exists
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            #uses function to set cookie
            self.login(u)
            self.redirect('/welcome')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        #returns user if it is valid username and password
        u = User.login(username, password)
        if u:
            #login on BlogHandler
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid Login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')


class WelcomeBlogger(BlogHandler):
    def get(self):
        if self.user:
            #self.user.name declared in inititalize function
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/signup', Register),
                               ('/welcome', WelcomeBlogger),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/addcomment/([0-9]+)', AddComment),
                               ('/blog/newpost', NewPost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/likepost/([0-9]+)', LikePost),
                               ('/blog/unlikepost/([0-9]+)', UnlikePost),
                               ('/blog/myblog', MyBlog)
                               ],
                                debug=True)
