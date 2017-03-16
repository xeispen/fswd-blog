import os
import re
import hmac
import hashlib
import string
import random
import jinja2
from model import *

# directory containing jinja html templates
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')

# instantiate jinja environment - looks for jinja templates
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
                               autoescape=True)

# hashing related functions
SECRET = 'imsosecret'

# checks that no email is supplied or email is valid
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

# checks that user input during user creation is valid
# a-z, 0-9, between 3 and 20 characters
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


# any characters between 3 and 20
PASS_RE = re.compile(r"^.{3,20}$")


def make_salt():
    """Creates salt which appends to end of hash"""
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    """Creates a hash of user's name and password along with random hash

    Args:
        name: user from User datastore class
        pw: user password
        salt: generated from make_salt()
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)


def valid_pw(name, pw, h):
    """Checks the user, password and salt to make sure it is valid

    Args:
        name: user from User datastore class
        pw: user password
        h: pw_hash from User datastore class
    Returns:
        h: pw_hash from User datastore class
    """
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)


def hash_str(s):
    """Takes in string and creates HMAC hash

    Args:
        s: string
    Returns:
        hmac hash with salt
    """
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    """Creates the hash that is stored in cookies

    Args:
        s: string
    Returns:
        HMAC hash
    """
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    """Splits the cookie stored into the
       original hash made by make_secure_val(s)

    Args:
        h: stored cookie
    Returns:
        val: the (s) arg from make_secure_val(s)
    """
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


# key related functions
def blog_key(name='default'):
    """ Returns the blog key """
    return db.Key.from_path('blogs', name)


def users_key(group='default'):
    """ Returns the user key """
    return db.Key.from_path('users', group)


# html rendering function
def render_str(template, **params):
    """ Jinja template rendering function """
    t = JINJA_ENV.get_template(template)
    return t.render(params)


def valid_username(username):
    """ Makes sure the entered username is valid """
    return username and USER_RE.match(username)


def valid_password(password):
    """ Makes sure the entered password is valid """
    return password and PASS_RE.match(password)


def valid_email(email):
    """ Makes sure the entered email is valid """
    return not email or EMAIL_RE.match(email)


def render_post(response, post):
    """ function renders post """
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def login_required(func):
    """
    A decorator to confirm a user is logged in or redirect as needed.
    """
    def login(self, *args, **kwargs):
        # Redirect to login if user not logged in, else execute func.
        if not self.user:
            self.redirect('/blog/login')
        else:
            func(self, *args, **kwargs)
    return login
