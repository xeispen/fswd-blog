import webapp2
import jinja2
from model import *
from helper import *


# class BlogHandler inherits from webapp2.RequestHandler
class BlogHandler(webapp2.RequestHandler):
    """ Main BlogHandler class and related functions"""
    def write(self, *a, **kw):
        """ eliminates need to retype self.response.out """
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """ returns string of rendered template """
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        """ calls write and render_str """
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """ convert val from unicode to str
            then function takes in name and val of cookie and sets it
        """
        cookie_val = make_secure_val(str(val))
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """ function reads a cookie and returns the cookie + hash """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """ function sets the cookie when user logs in """
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """ function clears the cookie upon logout """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def uid(self):
        """ if user is logged in, returns id, if not, none """
        if self.user:
            return self.user.key().id()
        else:
            return None

    def initialize(self, *a, **kw):
        """ checks if user is logged in or not """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        # sets local var user to uid and checks that this user exists
        self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):
    """ Class redirects to the blog """
    def get(self):
        """ Redirects to blog when /blog is hit """
        self.redirect('/blog/')


# handler for main blog URL
class BlogFront(BlogHandler):
    """ extends BlogHandler class for the main blog page """
    def get(self):
        """ Retrieves all blog posts regardless of user """
        posts = Post.all().order('-created')
        # ancestor query
        posts.ancestor(blog_key())
        params = dict(posts=posts, uid=self.uid())
        self.render("front.html", **params)

    @login_required
    def post(self):
        """ function creates a new blogpost """
        comment = self.request.get('comment')
        post_id = self.request.get('id')

        if self.user:
            uid = self.user.key().id()
            c = Comments(parent=blog_key(),
                         comment=comment,
                         user=int(uid),
                         post=int(post_id))
            c.put()
            self.redirect('/blog/')
        else:
            self.redirect('/blog/signup')


class PostPage(BlogHandler):
    """ Extends main bloghandler class for single post page """
    def get(self, post_id):
        """ make a key, find the post with post_id from url, whose parent is blog_key
            then looks up the blog post """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        params = dict(post=post, uid=self.uid())
        self.render("permalink.html", **params)

    @login_required
    def post(self, post_id):
        """ Post function for posting comments on individual post page """
        comment = self.request.get('comment')
        post_id = self.request.get('id')

        if self.user:
            uid = self.user.key().id()
            c = Comments(parent=blog_key(),
                         comment=comment,
                         user=int(uid),
                         post=int(post_id))
            c.put()
            self.redirect('/blog/%s' % post_id)
        else:
            self.redirect('/blog/signup')


class MyBlog(BlogHandler):
    """ Class extends main bloghandler class,
        for page displaying each user's own blog posts"""
    @login_required
    def get(self):
        """ Retrieves all of user's own blog posts """
        if self.user:
            posts = self.user.user_posts.order('-created')
            posts.ancestor(blog_key())
            params = dict(posts=posts, uid=self.uid())
            self.render("front.html", **params)
        else:
            self.redirect('/blog/signup')

    @login_required
    def post(self):
        """ post method for posting comments on this page """
        comment = self.request.get('comment')
        post_id = self.request.get('id')

        if self.user:
            uid = self.user.key().id()
            c = Comments(parent=blog_key(),
                         comment=comment,
                         user=int(uid),
                         post=int(post_id))
            c.put()
            self.redirect('/blog/myblog')
        else:
            self.redirect('/blog/signup')


class NewPost(BlogHandler):
    """ Extends main bloghandler class to page for creating new post """
    @login_required
    def get(self):
        """ Renders the new post page """
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect('/blog/signup')

    @login_required
    def post(self):
        """ Post method for creating new post """
        subject = self.request.get('subject')
        content = self.request.get('content')

        if self.user:
            if subject and content:
                p = Post(parent=blog_key(),
                         subject=subject,
                         content=content,
                         likes=0,
                         created_by=self.user)
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = "subject and content, please!"
                self.render("newpost.html",
                            subject=subject,
                            content=content,
                            error=error)
        else:
            self.redirect('/blog/signup')


class DeletePost(BlogHandler):
    """ Extends main bloghandler class for deleting post page """
    @login_required
    def get(self, post_id):
        """ make a key, find the post with post_id from url,
            whose parent is blog_key. Makes sure the user
            does not delete someone else's post
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        puid = post.poster_id()

        if self.user:
            uid = self.user.key().id()
            if int(uid) == puid:
                post.delete()
                return self.redirect('/blog/myblog')
            else:
                self.write("You didn't post that!!!")
        else:
            self.redirect('/blog/signup')


class EditPost(BlogHandler):
    """ Extends main bloghandler class for editing post page """
    @login_required
    def get(self, post_id):
        """make a key, find the post with post_id from url, whose parent is blog_key
            then makes sure that post is created by the user, if not, redirects
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        puid = post.poster_id()

        if self.user:
            uid = self.user.key().id()
            if int(uid) == puid:
                self.render('editpost.html',
                            subject=post.subject,
                            content=post.content)
            else:
                self.write("You can only edit your own posts!!!")
        else:
            self.redirect('/blog/signup')

    @login_required
    def post(self, post_id):
        """ Method posts changes that the user has edited"""
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        puid = post.poster_id()
        subject = self.request.get('subject')
        content = self.request.get('content')

        if self.user:
            uid = self.user.key().id()
            if int(uid) == puid:
                if subject and content:
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/blog/%s' % str(post.key().id()))
                else:
                    error = "subject and content, please!"
                    self.render("editpost.html",
                                pid=str(post_id),
                                subject=subject,
                                content=content,
                                error=error)
            else:
                self.write("You can only edit your own posts!!!")
        else:
            self.redirect('/blog/signup')


class LikePost(BlogHandler):
    """ Extends main blog handler to like a post"""
    @login_required
    def get(self, post_id):
        """ Makes sure the user liking the post did not create it, as well making sure
            they user has not already liked the post. If not,
            then allows user to like post
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        puid = post.poster_id()
        if self.user:
            uid = self.user.key().id()
            if uid != puid:
                if post.check_if_liked(uid):
                    self.write("You already liked this post!!!")
                else:
                    post.increment(uid)
                    self.redirect('/blog/')
            else:
                self.write("You can't like your own post!!!")
        else:
            self.redirect('/blog/signup')


class UnlikePost(BlogHandler):
    """ Extends main blog handler to like a post"""
    @login_required
    def get(self, post_id):
        """ Makes sure the user unliking the post did not create it, if not,
            as well as checking that the post was liked initially
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        puid = post.poster_id()

        if self.user:
            uid = self.user.key().id()
            if int(uid) != puid:
                if post.check_if_liked(uid):
                    post.decrease(uid)
                    self.redirect('/blog/')
                else:
                    self.write("You have not liked this post yet!!!")
            else:
                self.write("You can't unlike your own post!!!")
        else:
            self.redirect('/blog/signup')


class Signup(BlogHandler):
    """ Extends mainbloghandler class for the signup page """
    def get(self):
        """ Renders the signup form """
        self.render("signup-form.html")

    def post(self):
        """ Creates a new user """
        have_error = False
        # fetch parameters from request
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        # params sent back to rendering
        # always send back username and email
        params = dict(username=self.username,
                      email=self.email)

        # if there are issues, errors are added into params
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

        # if have_error is true, send back signup-form with params
        if have_error:
            self.render('signup-form.html', **params)
        # places username in url accessible by GET
        else:
            self.done()

    def done(self, *a, **kw):
        """ completes user creation """
        raise NotImplementedError


class Register(Signup):
    """ Extends the Signup class and its functions for user creation """
    def done(self):
        """ Creates new user and places in datastore """
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            # uses function to set cookie
            self.login(u)
            self.redirect('/blog/welcome')


class Login(BlogHandler):
    """ Extends mainbloghandler class for login page """
    def get(self):
        """ Renders login form """
        self.render('login-form.html')

    def post(self):
        """ Logs in user, checks for valid user and password """
        username = self.request.get('username')
        password = self.request.get('password')

        # returns user if it is valid username and password
        u = User.login(username, password)
        if u:
            # login on BlogHandler
            self.login(u)
            self.redirect('/blog/welcome')
        else:
            msg = 'Invalid Login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    """ Extends main bloghandler for logging out"""
    @login_required
    def get(self):
        """ Logs out, then redirects to signup """
        self.logout()
        self.redirect('/blog/signup')


class Profile(BlogHandler):
    """ Extends main bloghandler for logging out"""
    def get(self):
        """ Logs out, then redirects to signup """
        self.write("Under Construction! Check back later!")


class WelcomeBlogger(BlogHandler):
    """ Redirects from the welcome page, if user is logged in,
        redirects to blog page, if not, redirects to signup
    """
    @login_required
    def get(self):
        """ Checks if user is logged and then redirects appropriately """
        if self.user:
            # self.user.name declared in inititalize function
            # self.render('welcome.html', username = self.user.name)
            self.redirect('/blog/')
        else:
            self.redirect('/blog/signup')


app = webapp2.WSGIApplication([('/blog', MainPage),
                               ('/blog/signup', Register),
                               ('/blog/welcome', WelcomeBlogger),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/profile', Profile),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/likepost/([0-9]+)', LikePost),
                               ('/blog/unlikepost/([0-9]+)', UnlikePost),
                               ('/blog/myblog', MyBlog)], debug=True)
