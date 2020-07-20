import os
import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps


def lookup(country):
    url = "https://covid-19-data.p.rapidapi.com/country"

    querystring = {f"format":"json","name":{(country)}}

    headers = {
        'x-rapidapi-host': "covid-19-data.p.rapidapi.com",
        'x-rapidapi-key': "c3cce8be11msh0bc2296accd277bp18aab1jsn7e7227ca8f85"
        }

    response = requests.request("GET", url, headers=headers, params=querystring)
    data = response.json()
    for item in data:
        return {
            "name": item['country'],
            "confirmed": item['confirmed'],
            "recovered": item['recovered'],
            "critical": item['critical'],
            "deaths": item['deaths']
        }

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function