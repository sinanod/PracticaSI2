import pandas
import plotly.utils
from flask import Flask, render_template, request,redirect, session
import sqlite3
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from urllib.request import urlopen
import hashlib
import requests
from matplotlib import pyplot as plt
from sklearn import datasets, linear_model, tree
from sklearn.ensemble import RandomForestClassifier
from fpdf import FPDF
import os
import graphviz
from sklearn.tree import export_graphviz
from subprocess import call

app = Flask(__name__)

class PDF(FPDF):
    pass

fLegal = open('./assets/legal.json')
fUsers = open('./assets/users.json')
fClases = open('./assets/users_IA_clases.json')
fPredecir = open('./assets/users_IA_predecir.json')
dataLegal = json.load(fLegal)
dataUsers = json.load(fUsers)
dataClases = json.load(fClases)
dataPredecir = json.load(fPredecir)

df_critico = pd.DataFrame()
df_usuarios = pd.DataFrame()
df_admins = pd.DataFrame()
df_menorDoscientos = pd.DataFrame()
df_mayorDoscientos = pd.DataFrame()
df_legal = pd.DataFrame()
df_vulnerable = pd.DataFrame()
totalDF = pd.DataFrame()
df_privacidad = pd.DataFrame()
df_conexiones = pd.DataFrame()

X = []
usuariosX = []
usuariosY = []

for i in dataClases['usuarios']:
    array = []
    if(i['emails_phishing_clicados'] != 0):
        array.append(i['emails_phishing_clicados']/i['emails_phishing_recibidos'])
    else:
        array.append(0)

    usuariosY.append(i['vulnerable'])
    usuariosX.append(array)
    X.append([i['emails_phishing_clicados'], i['emails_phishing_recibidos']])

X_train = X[:-20]
X_test = usuariosX[-20:]
Y_train = usuariosY[:-20]
Y_test = usuariosY[-20:]
feature_names = ['Emails phishing cliclados', 'Emails phishing recibidos',]
target_names = ['No Vulnerable', 'Vulnerable']

'''def linear():
    print(usuariosX)
    print(usuariosY)
    print(X)
    regresion = linear_model.LinearRegression().fit(X_train, Y_train)
    coeficiente = regresion.coef_
    print(coeficiente.T[0])
    multi = []
    
    plt.scatter(X_test, Y_test)
    plt.plot(X_test, multi)
    pl
'''
def tree():
    clf = tree.DecisionTreeClassifier()
    clf = clf.fit(X_train, Y_train)
    dot_data = tree.export_graphviz(clf, out_file=None)
    graph = graphviz.Source(dot_data)
    dot_data = tree.export_graphviz(clf, out_file=None,
                                    feature_names=feature_names,
                                    class_names=target_names,
                                    filled=True, rounded=True,
                                    special_characters=True)
    graph = graphviz.Source(dot_data)
    graph.render('test.gv', view=True).replace('\\', '/')

def forest():
        clf = RandomForestClassifier(max_depth=2, random_state=0, n_estimators=10)
        clf.fit(X_train, Y_train)
        print(str(X_train[0]) + " " + str(Y_train[0]))
        print(clf.predict([X_train[0]]))

        for i in range(len(clf.estimators_)):
            print(i)
            estimator = clf.estimators_[i]
            export_graphviz(estimator,
                            out_file='tree.dot',
                            feature_names=feature_names,
                            class_names=target_names,
                            rounded=True, proportion=False,
                            precision=2, filled=True)
            call(['dot', '-Tpng', 'tree.dot', '-o', 'tree' + str(i) + '.png', '-Gdpi=600'])

def comprobarPassword(password):
    print("Comprobando contrasena:",password)
    md5hash = password
    try:
        password_list = str(urlopen("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt").read(),'utf-8')
        for password in password_list.split('\n'):
            guess = hashlib.md5(bytes(password, 'utf-8')).hexdigest()
            if guess == md5hash:
                return 1
            elif guess != md5hash:
                continue
            else:
                return 2
        return 2
    except Exception as exc:
        return 2

def probabilidadClick(cliclados,total):
    if (total!=0):
        return (cliclados/total) * 100
    else:
        return 0



#Comentamos la introducción de los datos para no tener que vaciar la base de datos y volver a rellenarla cada vez que ejecutamos los datos
'''con = sqlite3.connect('SISTINF.db')
cursorObj = con.cursor()
cursorObj.execute("DROP TABLE  legal")
cursorObj.execute("DROP TABLE  users")
cursorObj.execute("CREATE TABLE IF NOT EXISTS legal (url,cookie,aviso,proteccion,politica,creacion)")
cursorObj.execute("CREATE TABLE IF NOT EXISTS users (nombre,telefono,contrasena,provincia,permisos,emailsTot,emailsPhis,emailsClick,probClick, fechas, num_fechas, ips, num_ips, fortPass,primary key (nombre))")
insertLegal = """INSERT INTO legal (url,cookie,aviso,proteccion,politica,creacion) VALUES (?,?,?,?,?,?)"""
insertUsers = """INSERT INTO users (nombre,telefono,contrasena,provincia,permisos,emailsTot,emailsPhis,emailsClick,probClick, fechas, num_fechas, ips, num_ips, fortPass) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
for i in dataLegal['legal']:
    for j in i.keys():
        for k in i.values():
            datosLegal = (j, k['cookies'], k['aviso'], k['proteccion_de_datos'], k['cookies'] + k['aviso'] + k['proteccion_de_datos'], k['creacion'])
        cursorObj.execute(insertLegal, datosLegal)
        con.commit()

for i in dataUsers['usuarios']:
    for j in i.keys():
        for k in i.values():
            datosUsers = (j, k['telefono'], k['contrasena'], k['provincia'], k['permisos'], k['emails']['total'], k['emails']['phishing'], k['emails']['cliclados'],probabilidadClick(k['emails']['cliclados'],k['emails']['phishing']), str(k['fechas']), len(k['fechas']), str(k['ips']), len(k['ips']), comprobarPassword(k['contrasena']))
        cursorObj.execute(insertUsers, datosUsers)
        con.commit()

con.commit()'''

@app.route('/')
def inicio():
    return render_template("login.html")

@app.route('/index.html')
def index():
    return render_template("index.html")

usuarios = [["admin", "pass"], ["user", "pass"]]
app.secret_key = "Key"


@app.route('/login.html', methods=["GET", "POST"])
def login():
    if(request.method == "POST"):
        user = request.form.get('user')
        passwd = request.form.get('password')
        for i in range(len(usuarios)):
            if(usuarios[i][0] == user and usuarios[i][1] == passwd):
                session['user'] = user
                return redirect('index.html')

        return "Usuario o contraseña incorrectos"

    return render_template('login.html')

@app.route('/TopUsuariosCriticos.html', methods=["GET","POST"])
def topUssersCrit():
    num = request.form.get('numero', default=10)
    probNum = request.form.get('porcentaje',default='0')
    if(num==''):
        num = 10
    df_critico = pandas.DataFrame()
    con = sqlite3.connect('SISTINF.db')
    cursor_obj = con.cursor()

    if(probNum == '0'):
        query = """SELECT nombre,probClick FROM users where fortPass=1 ORDER BY probClick DESC LIMIT (?)"""
    elif(probNum == '1'):
        query = """SELECT nombre,probClick FROM users where fortPass=1 AND probClick>=50 ORDER BY probClick DESC LIMIT (?)"""
    elif(probNum =='2'):
        query = """SELECT nombre,probClick FROM users where fortPass=1 AND probClick<50 ORDER BY probClick DESC LIMIT (?)"""

    cursor_obj.execute(query, (num,))
    rows = cursor_obj.fetchall()
    nombre = []
    prob = []
    for i in range(len(rows)):
        nombre += [rows[i][0]]
        prob += [rows[i][1]]
    df_critico['Nombre'] = nombre
    df_critico['Probabilidad de Click'] = prob
    fig = px.bar(df_critico, x=df_critico['Nombre'], y=df_critico['Probabilidad de Click'])
    a = plotly.utils.PlotlyJSONEncoder
    graphJSONUsu = json.dumps(fig, cls=a)
    pdf = PDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()
    pdf_w = 210
    pdf_h = 297
    plotly.io.write_image(fig, file='pltx.png', format='png', width=700, height=450)
    pltx = (os.getcwd() + '/' + "pltx.png")
    pdf.set_xy(40.0, 25.0)
    pdf.image(pltx, link='', type='', w=700 / 5, h=450 / 5)
    pdf.set_font('Arial', '', 12)
    pdf.set_text_color(0, 0, 0)
    txt = "Top de usuarios críticos. En el eje X se muestran los nombres de los usuarios mientras que en el eje Y se muestra la probabilidad de click."
    pdf.set_xy(10.0, 130.0)
    pdf.multi_cell(w=0, h=10, txt=txt, align='L')
    pdf.output('static/topUsuariosCriticos.pdf', 'F')
    con.close()
    return render_template('TopUsuariosCriticos.html', graphJSONUsu=graphJSONUsu)

@app.route('/TopPaginasVulnerables.html', methods=["GET","POST"])
def topWebsVuln():
    num = request.form.get('numero', default=10)
    if (num == ''):
        num = 10
    print("00.33="+str(num));
    df_topWebs =pandas.DataFrame()
    con = sqlite3.connect('SISTINF.db')
    cursor_obj = con.cursor()
    query = """SELECT url,cookie,aviso,proteccion FROM legal ORDER BY politica LIMIT (?)"""
    cursor_obj.execute(query, (num,))
    rows = cursor_obj.fetchall()
    nombre = []
    cookies = []
    avisos = []
    proteccionDatos = []
    for i in range(len(rows)):
        nombre += [rows[i][0]]
        cookies += [rows[i][1]]
        avisos += [rows[i][2]]
        proteccionDatos += [rows[i][3]]
    df_topWebs['Nombre'] = nombre
    df_topWebs['Cookies'] = cookies
    df_topWebs['Avisos'] = avisos
    df_topWebs['Proteccion de Datos'] = proteccionDatos
    fig = go.Figure(data=[
        go.Bar(name='Cookies', x=df_topWebs['Nombre'], y=df_topWebs['Cookies'], marker_color='steelblue'),
        go.Bar(name='Avisos', x=df_topWebs['Nombre'], y=df_topWebs['Avisos'], marker_color='lightsalmon'),
        go.Bar(name='Proteccion de datos', x=df_topWebs['Nombre'], y=df_topWebs['Proteccion de Datos'], marker_color='red')
    ])
    fig.update_layout(title_text="Top paginas vulnerables", title_font_size=41, barmode='group')
    a = plotly.utils.PlotlyJSONEncoder
    graphJSONPag = json.dumps(fig, cls=a)
    pdf = PDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()
    pdf_w = 210
    pdf_h = 297
    plotly.io.write_image(fig, file='pltx.png', format='png', width=700, height=450)
    pltx = (os.getcwd() + '/' + "pltx.png")
    pdf.set_xy(40.0, 25.0)
    pdf.image(pltx, link='', type='', w=700 / 5, h=450 / 5)
    pdf.set_font('Arial', '', 12)
    pdf.set_text_color(0,0,0)
    txt="Top paginas vulnerables. En el eje X se muestran las paginas web mientras que en el eje Y semuestra la politica. "
    pdf.set_xy(10.0, 140.0)
    pdf.multi_cell(w=0, h=10, txt=txt,align='L')
    pdf.output('static/topPaginasVulnerables.pdf', 'F')
    return render_template('TopPaginasVulnerables.html', graphJSONPag=graphJSONPag)

@app.route('/Ultimas10Vulnerabilidades.html')
def ejerCuatro():
    page = requests.get("https://cve.circl.lu/api/last")
    jsons = page.json()
    listaCve = []
    listaSum = []
    for i in range(0,9):
        listaCve += [jsons[i]['id']]
        listaSum += [jsons[i]['summary']]
    fig = go.Figure(data=[go.Table(header=dict(values=['Vulnerabilidad','Descripcion']),cells=dict(values=[listaCve,listaSum]))])
    tabla = plotly.io.to_html(fig)
    return render_template('Ultimas10Vulnerabilidades.html',tablaHTMLVul=tabla)


#tree()
#forest()

if __name__ == '__main__':
    app.run()