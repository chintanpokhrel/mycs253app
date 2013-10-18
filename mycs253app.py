import webapp2 #the development framework
import cgi     #for html escaping (preventing Cross Site Scripting)
import re      #for regular expressions
import hashlib #for password hashing
import random
import json    #for loading json
import time    #for maintaining query time
import logging #for debugging
import os      #for jinja environment loading
import math

import jinja2  #jinja templating language version 2
import string

from google.appengine.ext import db #Google Datastore module
from google.appengine.api import memcache #memcached for appengine


jinja_environment = jinja2.Environment(autoescape=True,
                                       loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__),'templates')))



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile("^.{3,20}$")
EMAIL_RE= re.compile("^[\S]+@[\S]+\.[\S]+$")


#return a jinja2 template
def make_template(filename):
  return jinja_environment.get_template(filename)


#Set Login cookie
def set_cookie(cook,sender):
  sender.response.headers.add_header('Set-Cookie', 'Login=%s; Path=/'%cook)

#This is obvious, so no meaningful comment
def escape_html(s):
  return cgi.escape(s)


#Generates a random string of 5 letters for randomising hash 
def make_salt():
  return ''.join(random.choice(string.letters) for i in xrange(5))
 

#Generate the hash value
def make_password_hash(name,password,salt=None):
  if not salt:
    salt=make_salt()
  return hashlib.sha256(name+password+salt).hexdigest()+'|'+salt


#detects if a user is logged in
#Flagged: there should be a better way to this
def detect_login(sender):
  cookie=sender.request.cookies.get('Login')
  
  if not cookie:
    return None
  i=cookie.find('|')
  
  if i==-1:
    return None
  else:
    try:
      user=LoginInformation.get_by_id(int(cookie[:i]))
    except Exception:
      return None
  return user


#signup, login, logout etc.. starts here!!

#This class represents the datastore object representing Login Information
class LoginInformation(db.Model):
  username=db.StringProperty(required=True)
  password_hash=db.StringProperty(required=True)
  email=db.StringProperty()

  
#Handler for /signup
class SignupHandler(webapp2.RequestHandler):
  
  #Checks 1.  if user already exists 2. if username given matches the required regexp
  def valid_username(self,username):
    login=db.GqlQuery("SELECT * FROM LoginInformation where username=:1",username)
    login=list(login)
    if login:
      return False,'User already exists'
    if USER_RE.match(username):
      return True,''
    return False,'This is not a valid username.'
  
  #Checks if password given matches required regexp
  def valid_password(self,password):
    if PASS_RE.match(password):
      return True,''
    return False,'That was not a valid password.'

  #Checks if email given matches required regexp
  def valid_email(self,email):
    if EMAIL_RE.match(email) or email=='':
      return True,''
    return False,'That was not a valid email'

  #Writes the form to browser
  def write_form(self,referer_url,username="",email="",user_error="",pass_error="",verify_error="",mail_error=""):
    template=make_template('signup.html')
    message={"username":username,
             "email":email,
             "user_error":user_error,
             "pass_error":pass_error,
             "verify_error":verify_error,
             "mail_error":mail_error,
             "referer_url":referer_url}
    
    self.response.out.write(template.render(message))

  #HTTP GET method for signup page
  def get(self):
    self.write_form(referer_url=self.request.referer)

  #HTTP POST method for receiving, validating and saving signup form data
  def post(self):
    username=self.request.get("username")
    password=self.request.get("password")
    verify=self.request.get("verify")
    email=self.request.get("email")
    referer_url=str(self.request.get("referer"))
    uvalid,user_error=self.valid_username(username)
    pvalid,pass_error=self.valid_password(password)
    evalid,mail_error=self.valid_email(email)
    verify_error=''
    if verify!=password:
      verify_error='Passwords do not match'

    if uvalid and pvalid and (verify==password) and evalid:
      password_hash=make_password_hash(username,password)
      #Add record to database
      l=LoginInformation(username=username,password_hash=password_hash,email=email)
      l.put()
      key=l.key().id()
      #Set cookie
      set_cookie(str(key)+'|'+str(password_hash[:-6]),self)
      if referer_url==self.request.url:
        self.redirect('/welcome')
      else:
        self.redirect(referer_url)
      
    self.write_form(referer_url,escape_html(username),escape_html(email),user_error,pass_error,verify_error,mail_error)


#Handler for /login
class LoginHandler(webapp2.RequestHandler):
  
  def render_form(self,referer_url,username="",error=""):
    template=make_template('login.html')
    self.response.out.write(template.render({"username":username,"error":error,'referer_url':referer_url}))
  
  def get(self):
    self.render_form(referer_url=self.request.referer)

  #HTTP POST method to handle login data
  def post(self):
    
    username=self.request.get("username")
    password=self.request.get("password")
    referer_url=str(self.request.get('referer'))
    error=""
    login=db.GqlQuery("SELECT * FROM LoginInformation WHERE username=:1",username)
    login=list(login)
    
    if login:
      salt=login[0].password_hash[-5:]
      
      if make_password_hash(username,password,salt)==login[0].password_hash:
        set_cookie(str(login[0].key().id())+'|'+str(login[0].password_hash[:-6]),self)
        self.redirect(referer_url)
      else:
        error="Username and password do not match."
        
    else:
      error='User does not exist.'
      
    self.render_form(referer_url,escape_html(username),error)


class LogoutHandler(webapp2.RequestHandler):

  
  def get(self):
    #Empty the login cookie
    self.response.headers.add_header('Set-Cookie', 'Login=; Path=/')

    #If logout was clicked on some page then redirect to that (referer) page
    if self.request.referer:
      self.redirect(self.request.referer)
    #If it was directly typed into the address bar then redirect to /signup
    else:
      self.redirect('/signup')


      
class FlushHandler(webapp2.RequestHandler):
  
  def get(self):
    memcache.flush_all()
    self.redirect('/')


def render_str(template,**params):
    template=make_template('post.html')
    return template.render(params)


#Blog starts here
class Posts(db.Model):

  subject = db.StringProperty(required = True)
  blog = db.TextProperty(required = True)
  posted =db.DateTimeProperty(auto_now_add = True)


  def render(self):
    self.render_text = self.blog.replace('\n', '<br>')
    return render_str("post.html", p = self)


  def render_summary(self):
    return render_str('post_summary.html', p = self)
  

def update_mainpage(key, page_no=1):
  memcache.set('querytime' + str(page_no), round(time.time())) 
  #This is kinda expensive, I need a better way to do this.
  posts=db.GqlQuery('SELECT * FROM Posts ORDER BY posted DESC') # DESC LIMIT :1', page_no*10) Intended at least this, but isn't working
  posts=(list(posts))[(page_no-1)*10:(page_no-1)*10+10]
  memcache.set(key,posts)
  logging.error(memcache.get(key))
  
    
class BlogMainPageHandler(webapp2.RequestHandler):

  
  def escape_html(self,s):
    return cgi.escape(s,quote=True)


  def top_posts(self, page_no=1):
    key = 'page' + str(page_no)
    posts = memcache.get(key)
    
    if not posts:
      update_mainpage(key, page_no)
      posts = memcache.get(key)
      
    return posts
  
  
  def render_front_page(self, page_no=1):
    if(page_no == None or page_no == ''):
      page_no = 1
      
    page_no = int(page_no)
    posts=self.top_posts(page_no)
    i=0
    post_index=0
    page={}
    page['posts']=posts
    page['user']=self.user
    page['next_page_no'] = page_no + 1
    
    if self.user:
      page['user.username']=self.user.username
      
    template=make_template('main.html')
    querytime=memcache.get('querytime'+str(page_no))
    
    if not querytime:
      querytime=round(time.time())
      
    page['querytime']=str(round(time.time())-querytime)
    self.response.out.write(template.render(page))

    
  def get(self, page_no):
    self.user=detect_login(self)
    self.render_front_page(page_no)



class NewPostHandler(webapp2.RequestHandler):


  def escape_html(self,s):
    return cgi.escape(s,quote=True)

  
  def render_form(self,subject='',blog='',error=''):
    template=make_template('newpost.html')
    self.response.out.write(template.render({'subject':subject,'blog':blog,'error':error,'user':self.user}))

    
  def get(self):
    self.user=detect_login(self)
    
    if not self.user:
      self.redirect('/login',permanent=True)
      
    self.render_form()


  def post(self):
    new_subject=(self.request.get('subject')).lstrip()
    new_blog=(self.request.get('content')).lstrip()
    
    error=''
    if new_subject=='' or new_blog=='' :
      error='Subject and content please!'
      self.render_form(self.escape_html(new_subject),self.escape_html(new_blog),error)
    else:
      key='page1'
      p=Posts(subject=new_subject,blog=new_blog)
      p.put()
      update_mainpage(key)
      self.redirect('/blog/'+str(p.key().id()))


def update_permalinkpage(identifier):
  memcache.set('querytime'+str(identifier),round(time.time()))
  post=Posts.get_by_id(identifier)
  memcache.set('permalink'+str(identifier),post)
  
  return post


def get_permalinkpost(identifier):
  
  post=memcache.get('permalink'+str(identifier))
  
  if not post:
    post=update_permalinkpage(identifier)
    
  return post

	
#The permalink pages are not cached
class PermalinkHandler(webapp2.RequestHandler):
  
  def escape_html(self,s):
    return cgi.escape(s,quote=True)

  
  def get(self):
    url=self.request.url
    identifier=""
    
    for e in url[::-1]:
      if not e.isdigit():
        break
      identifier+=e

    identifier=int(identifier[::-1])
    post=get_permalinkpost(identifier)
  
    if post==None:
      self.abort(404)
    else:
      template=make_template('permalink.html')
      self.response.out.write(template.render({'post':post,
                                               'querytime':str(round(time.time())-memcache.get('querytime'+str(identifier)))}
                                              )
                              )


      
class MainPageJsonHandler(webapp2.RequestHandler):
    
    def escape_json(self,s):
        t=''
        i=0
        while i in range(0,len(s)):
            if s[i] == '\'':
                t+= '\\\''
            else:
              if s[i] == '\"':
                t+= '\\\"'
              else:
                t+=s[i]
            i=i+1

        return s
                
            
    def get(self):
        myjson = []
        posts=db.GqlQuery("SELECT * FROM Posts ORDER BY posted DESC LIMIT 10")

        for post in posts:
            d={'content':'','created':'','subject':''}
            d['subject']=self.escape_json(post.subject)
            d['content']=self.escape_json(post.blog)
            d['created']=self.escape_json(post.posted.strftime("%a %b %d")+str(post.posted.year)+post.posted.time().strftime("%H:%M:%S"))
            myjson.append(d)
        self.response.headers['Content-Type']='application/json'
        self.response.out.write(json.dumps(myjson))


class PermalinkPageJsonHandler(webapp2.RequestHandler):

  
    def escape_json(self,s):
        t=''
        i=0
        while i in range(0,len(s)):
            if s[i] == '\'':
                t+= '\\\''
            else:
              if s[i] == '\"':
                t+= '\\\"'
              else:
                t+=s[i]
            i=i+1

        return s

  
    def get(self):
        url=self.request.url
        url=url[::-1]
        identifier=""
        
        for e in url[5:]:
            if e not in ['0','1','2','3','4','5','6','7','8','9']:
                break
            identifier+=e
            
        identifier=int(identifier[::-1])
        post=Posts.get_by_id(identifier)

        if post==None:
            self.abort(404)
            
        d={'content':'','created':'','subject':''}
        myjson=[]
        d['subject']=self.escape_json(post.subject)
        d['content']=self.escape_json(post.blog)
        d['created']=self.escape_json(post.posted.strftime("%a %b %d")+str(post.posted.year)+post.posted.time().strftime("%H:%M:%S"))
        myjson.append(d)
        self.response.headers['Content-Type']= 'application/json'
        self.response.out.write(json.dumps(myjson))
        
        
    
                                
#WSGI url router
app = webapp2.WSGIApplication([('/?()',BlogMainPageHandler),
                               (r'/(\d+)',BlogMainPageHandler),
                               ('/login/?',LoginHandler),
                               ('/logout/?',LogoutHandler),
                               ('/signup/?',SignupHandler),
                               ('/blog/.json/?',MainPageJsonHandler),
                               (r'/blog/\d+.json/?',PermalinkPageJsonHandler),
                               ('/newpost/?',NewPostHandler),
                               (r'/blog/\d+/?',PermalinkHandler),
                               ('/blog/flush/?',FlushHandler)],
                              debug=True)
                              
