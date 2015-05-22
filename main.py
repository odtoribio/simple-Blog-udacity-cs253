import re
import logging
import json
from string import letters
import os
import jinja2
import webapp2
import random
import string
import hashlib
import hmac

from datetime import datetime, timedelta
from google.appengine.api import memcache
from google.appengine.ext import db

form = """
        <html>
<head>
    <title>Sign up user</title>
    <style type="text/css">
    .label{text-align: right;}
    .error{color: red}
    </style>
</head>
<body>
    <h2>Signup</h2>
    <form method="post">
        <table>
            <tr>
                <td class="label">
                    Username
                </td>
                <td>
                    <input type="text" name="username" value="%(name)s">
                </td>
                <td class="error">
                    %(username_error)s
                </td>
            </tr>
            <tr>
                <td class="label">
                    Password
                </td>
                <td>
                    <input type="password" name="password" value="">
                </td>
                <td class="error">
                    %(password_error)s
                </td>
            </tr>
            <tr>
                <td class="label">
                    Verify password
                </td>
                <td>
                    <input type="password" name="verify" value="">
                </td>
                <td class="error">
                    %(verify_error)s
                </td>
            </tr>
            <tr>
                <td class="label">
                    Email(optional)
                </td>
                <td>
                    <input type="text" name="email" value="%(em)s">
                </td>
                <td class="error">
                    %(email_error)s
                </td>
            </tr>

            <br>
            <br>

        </table>
        <input type="submit">
    </form>

</body>
</html>
"""

form2="""
    <!DOCTYPE html>

<html>
  <head>
    <title>Login</title>
    <style type="text/css">
      .label {text-align: right}
      .error {color: red}
    </style>

  </head>

  <body>
    <h2>Login</h2>
    <form method="post">
      <table>
        <tr>
          <td class="label">
            Username
          </td>
          <td>
            <input type="text" name="username" value="">
          </td>
        </tr>

        <tr>
          <td class="label">
            Password
          </td>
          <td>
            <input type="password" name="password" value="">
          </td>
        </tr>
      </table>

      <div class="error">
        %(error)s
      </div>

      <input type="submit">
    </form>
  </body>

</html>

"""

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape= True)


def write(self,*a,**kw):
    self.response.write(*a,**kw)

def render_str(self,template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def render(self,template,**kw):
    self.write(self.render_str(template,**kw))




#to make  and chek values fo cookies

secret = 'oscar'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val



class MainHandler(webapp2.RequestHandler):

    username_error = ""
    password_error =""
    verify_error = ""
    email_error = ""
    name = ""
    em=""

    def valid_username(self,username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        status = USER_RE.match(username)

        if status == None:
            self.username_error = "That's not valid Username"
            return False
        else:
            self.name = username
            return True

    def valid_email(self,email):
        email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        status = email_re.match(email)

        if (status != None) or (not email):
            self.em = email
            return True
        else:
            self.email_error = "That's not valid email"
            return False

    def valid_password(self,password,verify):
        password_re = re.compile(r"^.{3,20}$")

        if not password:
            self.password_error = "That's wasn't a valid password"
            return False
        else:
            status = password_re.match(password)
            if (status != None):
                if password == verify:
                    return True
                else:
                    self.verify_error = "Your passwords didn't match"
                    return False
            else:
                self.password_error = "That's wasn't a valid password"
                return False

    def user_is_free(self,username):
        u = DB.all().filter('user =', username).get()
        if u:
            self.username_error = "User already exists."
            return False
        else:
            return True

    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5))

    def make_pw_hash(self,name, pw, salt = None):
        if not salt:
            salt = self.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (h, salt)

    def valid_pw(self,name, pw, h):
        x= h.split(',')[1]
        return h == self.make_pw_hash(name,pw,x)


    #for cookies

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))


class DB(db.Model):

    user = db.StringProperty(required = True)
    hash_ps = db.StringProperty(required = True)
    email =db.StringProperty()

username_glob = None

class Register(MainHandler):

    def get(self):

        self.response.write(form %{"em":self.em,"name":self.name,"username_error":self.username_error,
                                   "password_error" : self.password_error, "verify_error":self.verify_error, "email_error" :self.email_error} )

        x = self.read_secure_cookie("user_id")


    def post(self):

        #reading data and saving in the var
        user = self.request.get("username")
        password = self.request.get("password")
        email = self.request.get("email")
        hs_password = self.make_pw_hash(user,password)
        global username_glob
        username_glob = user


        # next ver returns boolean
        username = self.valid_username(self.request.get("username"))
        password_v = self.valid_password(self.request.get("password"), self.request.get("verify"))
        e_mail = self.valid_email(self.request.get("email"))
        if username and self.user_is_free(user):
            if  password_v and e_mail:
                u = DB(user = user,hash_ps = hs_password , email = email)
                u.put()
                self.login(u)
                self.redirect('/welcome')
            else:
                self.response.write(form %{"em":self.em,"name":self.name,"username_error":self.username_error,
                                       "password_error" : self.password_error, "verify_error":self.verify_error, "email_error" :self.email_error})

        else:
            self.response.write(form %{"em":self.em,"name":self.name,"username_error":self.username_error,
                                       "password_error" : self.password_error, "verify_error":self.verify_error, "email_error" :self.email_error})

class Welcome(Register):

    global username_glob
    def get(self):
        x = self.request.cookies.get("user_id")
        id_user = check_secure_val(x)
        if id_user and DB.get_by_id(int(id_user)):
        #user_loged = self.request.get("username")
            self.response.write("Welcome, "+ username_glob +"!")
        else:
            self.redirect('/signup')

class Login(MainHandler):
    def get(self):
        self.response.write(form2 %{"error":""})


    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        global username_glob
        username_glob = username
        u = DB.all().filter('user =', username).get()
        if u and self.valid_pw(username,password,u.hash_ps):
            self.set_secure_cookie('user_id', str(u.key().id()))
            #self.login(username)
            self.redirect('/welcome')
        else:
            error = "Invalid login"
            self.response.write(form2 %{"error":error})

class Logout(MainHandler):
    def get(self):
        cookie = ""
        self.response.headers.add_header('Set-Cookie','user_id=%s; Path=/' %(cookie))
        self.redirect("/signup")

class Handler(webapp2.RequestHandler):

    def write(self,*a,**kw):
        self.response.write(*a,**kw)

    def render_str(self,template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

# to set time in memcache

def time_set(key,val):
    new_time = datetime.utcnow()
    memcache.set(key,(val,new_time))


def time_get(key):

    r = memcache.get(key)

    if r:
        val , old_time = r
        time = (datetime.utcnow() - old_time).total_seconds()
    else:
        val , time = None,0
    return val , time

def add_post(post):

    post.put()
    get_posts(update = True)
    return str(post.key().id())

def get_posts(update = False):

    mc_key = 'BLOGS'
    posts,time = time_get(mc_key)

    if update or posts is None:
        q =  db.GqlQuery("SELECT * FROM Data ORDER BY created DESC")
        posts = list(q)
        time_set(mc_key,posts)

    return posts , time

def time_str(time):
    s = 'queried %s seconds ago'
    time = int(time)
    return s % time

class MainPage(Handler):

    def get(self):

        data,time = get_posts()
        data = db.GqlQuery("SELECT * FROM Data ORDER BY created DESC")
        if self.format == 'html':
            self.render("blog.html",data = data , time = time_str(time))
        else:
            return self.render_json([p.as_dict() for p in data])

class Data(db.Model):

    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    def render(self):
        self._render_text = self.content.replace('/n', '<br>')
        return self.render_str("lastpost.html", post = self)

    def as_dict(self):
        d = {'subject': self.subject,
             'content': self.content}
        return d

class LastPost(Handler):

    def get(self, post_id):
        post_key = 'POST_'+post_id

        post , time = time_get(post_key)

        if not post:
            key = db.Key.from_path("Data",int(post_id))
            post = db.get(key)
            time_set(post_key,post)
            time = 0

        if not post:
            self.error(404)
            return
        if self.format == 'html':
            self.render("lastpost.html", post = post , time = time_str(time))
        else:
            self.render_json(post.as_dict())#editar aqui todavia

class NewPost(Handler):

    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:

            a = Data(subject = subject,content=content)
            a.put()
            self.redirect("/%s" % str(a.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",subject= subject, content= content, error=error)

class Flush(MainHandler):
    def get(self):
        memcache.flush_all()
        self.redirect("/")

app = webapp2.WSGIApplication([
    ('/?(?:.json)?', MainPage),
    ('/newpost', NewPost),
    ('/([0-9]+)(?:.json)?', LastPost),
    ('/signup', Register),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/logout',Logout),
    ('/flush',Flush)
], debug=True)
