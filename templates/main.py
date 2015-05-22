import os
import jinja2
import webapp2
import random

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape= True)

class Handler(webapp2.RequestHandler):

    def write(self,*a,**kw):
        self.response.write(*a,**kw)

    def render_str(self,template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))



class MainPage(Handler):

    def get(self):
        data = db.GqlQuery("SELECT * FROM Data ORDER BY created DESC")
        self.render("blog.html",data = data)

class Data(db.Model):

    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    def render(self):
        self._render_text = self.content.replace('/n', '<br>')
        return self.render_str("lastpost.html", post = self)

class LastPost(Handler):

    def get(self, post_id):
        key = db.Key.from_path("Data",int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return
        self.render("lastpost.html", post = post)

class NewPost(Handler):

    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:

            a = Data(subject = subject,content=content)
            a.put()
            self.redirect("/blog/%s" % str(a.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",subject= subject, content= content, error=error)



app = webapp2.WSGIApplication([
    ('/blog/?(?:.json)?', MainPage),
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)(?:.json)?', LastPost)
], debug=True)
