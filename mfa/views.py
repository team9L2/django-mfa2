from django.shortcuts import render
from django.http import HttpResponse,HttpResponseRedirect
from .models import *
try:
    from django.urls import reverse
except:
    from django.core.urlresolvers import reverse
from django.template.context_processors import csrf
from django.template.context import RequestContext
from django.conf import settings
from . import TrustedDevice
from django.contrib.auth.decorators import login_required
from user_agents import parse

@login_required
def index(request):
    keys=[]
    context={"keys":User_Keys.objects.filter(username=request.user.username),"UNALLOWED_AUTHEN_METHODS":settings.MFA_UNALLOWED_METHODS
             ,"HIDE_DISABLE":getattr(settings,"MFA_HIDE_DISABLE",[])}
    for k in context["keys"]:
        if k.key_type =="Trusted Device" :
            setattr(k,"device",parse(k.properties.get("user_agent","-----")))
        elif k.key_type == "FIDO2":
            setattr(k,"device",k.properties.get("type","----"))
        keys.append(k)
    context["keys"]=keys
    return render(request,"MFA.html",context)

def verify(request,username):
    request.session["base_username"] = username
    #request.session["base_password"] = password
    keys=User_Keys.objects.filter(username=username,enabled=1)
    methods = list({k.key_type for k in keys})

    if "Trusted Device" in methods and not request.session.get("checked_trusted_device",False):
        if TrustedDevice.verify(request):
            return login(request)
        methods.remove("Trusted Device")
    request.session["mfa_methods"] = methods
    if len(methods)==1:
        return HttpResponseRedirect(reverse(f"{methods[0].lower()}_auth"))
    return show_methods(request)

def show_methods(request):
    return render(request,"select_mfa_method.html", {})

def reset_cookie(request):
    response=HttpResponseRedirect(settings.LOGIN_URL)
    response.delete_cookie("base_username")
    return response
def login(request):
    from django.contrib import auth
    from django.conf import settings
    callable_func = __get_callable_function__(settings.MFA_LOGIN_CALLBACK)
    return callable_func(request,username=request.session["base_username"])


@login_required
def delKey(request):
    key=User_Keys.objects.get(id=request.GET["id"])
    if key.username != request.user.username:
        return HttpResponse("Error: You own this token so you can't delete it")
    key.delete()
    return HttpResponse("Deleted Successfully")

def __get_callable_function__(func_path):
    import importlib
    if '.' not in func_path:
        raise Exception("class Name should include modulename.classname")

    parsed_str = func_path.split(".")
    module_name , func_name = ".".join(parsed_str[:-1]) , parsed_str[-1]
    imported_module = importlib.import_module(module_name)
    callable_func = getattr(imported_module,func_name)
    if not callable_func:
        raise Exception("Module does not have requested function")
    return callable_func

@login_required
def toggleKey(request):
    id=request.GET["id"]
    q=User_Keys.objects.filter(username=request.user.username, id=id)
    if q.count() != 1:
        return HttpResponse("Error")
    key=q[0]
    if key.key_type in settings.MFA_HIDE_DISABLE:
        return HttpResponse("You can't change this method.")
    key.enabled=not key.enabled
    key.save()
    return HttpResponse("OK")

def goto(request,method):
    return HttpResponseRedirect(reverse(f"{method.lower()}_auth"))
