import os
import pathlib
import requests
from flask import Flask, session, abort, redirect, request, url_for, render_template
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from functools import wraps  # Importar wraps para evitar conflictos con nombres de funciones

app = Flask("Google Login App")
app.secret_key = "CodeSpecialist.com"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "722353237973-ctg2m0lvn9j7dc1q7big2578eqp3ccl1.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# Lista de correos autorizados
authorized_emails = ['luisa.arias.roldan805@gmail.com', 'jhonatan.sancheznick@gmail.com']

# Decorador actualizado para evitar conflicto de nombres
def login_is_required(function):
    @wraps(function)  # Preserva el nombre original de la función
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        return function(*args, **kwargs)
    return wrapper

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials

    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,  # Cambiado de _id_token a id_token
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    email = id_info.get("email")  # Obtén el correo del usuario
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = email

    # Verificar si el correo está en la lista de correos autorizados
    if email not in authorized_emails:
        return "Acceso denegado. Tu correo no está autorizado para ingresar."

    # Redirige a la ruta TIC si el correo es autorizado
    return redirect(url_for('tic'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
def index():
    return render_template('inicio.html')

@app.route("/protected_area")
@login_is_required
def protected_area():
    return f"""
        Hello {session['name']}! <br/>
        <a href='/logout'><button>Logout</button></a>
    """

# Nuevas rutas
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    return render_template('contact.html')

@app.route('/inicio', methods=['GET', 'POST'])
def inicio():
    return render_template('inicio.html')

@app.route('/TIC', methods=['GET', 'POST'])
@login_is_required
def tic():
    return render_template('TIC.html')

@app.route('/login_page', methods=['GET', 'POST'])
def login_page():
    return render_template('login.html')

# Redireccionando cuando la página no existe
@app.errorhandler(404)
def not_found(error):
    return 'Ruta no encontrada', 404

if __name__ == "__main__":
    app.run(debug=True, port=5000)
