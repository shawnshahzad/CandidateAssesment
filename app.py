import json
import jwt
import datetime
import time
from os import environ as env
from re import X
from urllib.parse import quote_plus, urlencode
import urllib.parse
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, jsonify, request, make_response, redirect, render_template, session, url_for, flash
from flask_mail import Mail, Message

import requests
from werkzeug.datastructures import ImmutableMultiDict
from functools import wraps
from flask_mysqldb import MySQL

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'db_sample'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

app.secret_key = env.get("APP_SECRET_KEY")

app.config['MAIL_SERVER'] = env.get("MAIL_SERVER")
app.config['MAIL_PORT'] = int(env.get("MAIL_PORT"))
app.config['MAIL_USERNAME'] = env.get("QUIZ_EMAIL")
app.config['MAIL_PASSWORD'] = env.get("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = env.get("MAIL_USE_TLS") == 'True'
app.config['MAIL_USE_SSL'] = env.get("MAIL_USE_SSL") == 'True'

# print(app.static_folder)
# print(app.template_folder)

mail = Mail()
mail.init_app(app)

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    # authorize_url =f'https://{env.get("AUTH0_DOMAIN")}/authorize',
    # access_token_url=f'https://{env.get("AUTH0_DOMAIN")}/oauth/token',
    # api_base_url=f'https://{env.get("AUTH0_DOMAIN")}'
    server_metadata_url = f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

#Login
def is_logged_in(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = session.get('user')
        current_path = request.path
        quoted_path = urllib.parse.quote(current_path,safe='')
        if user:
            return f(*args, **kwargs)
        return redirect(url_for("login", _external=True) + '?from=' +quoted_path)
    return decorated

# # Registration
@app.route('/reg',methods=['POST','GET'])
def reg():
    status=False
    if request.method=='POST':
        name=request.form["uname"]
        email=request.form["email"]
        pwd=request.form["upass"]
        cur=mysql.connection.cursor()
        cur.execute("insert into users(UNAME,UPASS,EMAIL) values(%s,%s,%s)",(name,pwd,email))
        mysql.connection.commit()
        cur.close()
        flash('Registration Successfully. Login Here...','success')
        return redirect('login')
    return render_template("reg.html",status=status)


# Home page
@app.route("/dashboard", methods=['POST', 'GET'])
@is_logged_in
def dashboard():
    user = session["UID"]
    return render_template('dashboard.html', uid=user)


# preview page
@app.route("/preview", methods=['POST', 'GET'])
@is_logged_in
def preview():
    if request.method == 'POST':
        result = request.form
        Table = []
        for key, value in result.items():
            temp = []
            temp.extend([key,value])
            Table.append(temp)
        q = request.form
        '''print(q)'''
        json_stuff= (q.to_dict(flat=False))
        qname = None
        for i in json_stuff.keys():
            if json_stuff[i] == ['Submit']:
                qname = i
        json_data = str(json_stuff)
        '''convert to json string double quotes'''
        json_string = json.dumps(json_data)
        '''open database connnection, add user defined quiz into database and close connection'''
        cur=mysql.connection.cursor()
        '''global variable which holds UID'''
        x = user = session["UID"]

        cur.execute("insert into quizinformation(UID,dataz, qname) values(%s,%s,%s)",(x,json_string,qname))

        mysql.connection.commit()
        cur.close()

        """to display in preview.html"""
        # print(json_stuff)

        #to extract the time for the quiz
        time_as_list = json_stuff['minutes']
        time_as_str = ''.join(time_as_list)
        time_no_brackets = time_as_str.strip("['']")
        quiz_time = int(time_no_brackets)
        return render_template("preview.html",
                               json_stuff = json_stuff,
                               quiz_time=quiz_time,
                               send_quizzes=url_for('send_quizzes',_external=True),
                               qname=qname,
                               edit_quiz=url_for('edit_quiz',
                                                 UID=x,
                                                 qname=qname,
                                                 _external=True
                                                 )
                               )





@app.route("/new_quiz/<UID>/<qname>", methods=['POST', 'GET'])
@is_logged_in
def new_quiz(UID, qname):
    original_quiz_name = qname.replace("_", ' ')
    return render_template('new_quiz.html',
                           qname=original_quiz_name,
                           URL=qname,
                           post2=url_for('preview',_external=True)
                           )


@app.route("/quiz_name/<UID>", methods=['POST', 'GET'])
@is_logged_in
def quiz_name(UID):
    user = session["UID"]
    if request.method == "POST":
        qname = request.form['quiz_name']
        qname = qname.replace(" ", '_')
        return redirect(url_for('new_quiz', UID=user, qname=qname))
    return render_template('quiz_name.html', uid=user)


@app.route("/existing_quizzes/<UID>", methods=['POST', 'GET'])
@is_logged_in
def existing_quizzes(UID):
    user = str(session["UID"])
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM quizinformation WHERE UID = %s", user)
    data = cur.fetchall()
    conv_list = []

    for j in range(len(data)):
        conv = json.loads(data[j]['dataz'])
        conv = conv.replace("'", '"')
        conv2 = json.loads(conv)
        conv_list.append(conv2)

    names = []
    URL_names = []
    for k in conv_list:
        for l in k.keys():
            if k[l] == ['Submit']:
                names.append(l)
                URL = l.replace(" ", '_')
                URL_names.append(URL)
    return render_template('existing_quizzes.html', names=names, UID=user, URL=URL_names)

@app.route("/edit_quiz/<UID>/<qname>", methods=['POST', 'GET'])
@is_logged_in
def edit_quiz(UID, qname):
    qname = qname.replace('_', ' ')
    user = str(session["UID"])
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM quizinformation WHERE UID = %s", user)
    data = cur.fetchall()

    match = None
    conv_list = []
    for j in range(len(data)):
        conv = json.loads(data[j]['dataz'])
        conv = conv.replace("'", '"')
        conv2 = json.loads(conv)
        conv_list.append(conv2)
    # print(conv_list)
    for k in conv_list:
        for l in k.keys():
            if l == qname:
                match = k

    # Q/As are split up into R_ + question number
    question = 'R_'
    cur_question = 1
    correct_answer = 'A_'
    # Breaks Questions and answers up from the dictionary to a list to
    # make processing possible back at the form
    num_answers_list = []
    questions = []
    answers = []
    correct_answers = []
    ans_text_box_ids = []
    answers_by_q = []
    row_idxes = [];
    for q_key in match:
        # print(q_key)
        if q_key.split('_')[0] == question.split('_')[0]:
            question_num = 'ques_' + str(cur_question)
            num_answers_list.append(len(match[q_key])-1)
            questions.append([question_num, match[q_key][0]])
            answers_by_q.append(match[q_key][1::])
            for ans in match[q_key][1::]:
                # print('  ', ans)
                answers.append(ans)
            cur_question += 1
        elif q_key.split('_')[0] == correct_answer.split('_')[0]:
            # print(match[q_key])
            correct_answers.append(match[q_key])
    # print(correct_answers)

    # Will absolutely have issues if more than 10 answers are given.
    cur_q = 1
    for j in num_answers_list:
        cur_text_box_id = 1
        for k in range(j):
            ans_text_box_ids.append('txt_' + str(cur_text_box_id) + '00' + str(cur_q))
            cur_text_box_id += 1
        cur_q += 1

    minutes = match['minutes']
    minutes[0] = int(minutes[0])
    emails = match['email']

    total_answers = sum(num_answers_list)
    return render_template('edit_quiz.html',
                           num_questions=cur_question - 1,
                           num_answers_list=num_answers_list,
                           questions=questions,
                           ans_tbs=ans_text_box_ids,
                           answers=answers,
                           minutes=minutes,
                           emails=emails,
                           total_answers=total_answers,
                           qname=qname,
                           correct_answers=correct_answers,
                           answers_by_q=answers_by_q)


@app.route("/send_quizzes", methods=['POST', 'GET'])
@is_logged_in
def send_quizzes():
    user = str(session["UID"])
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM quizinformation WHERE UID = %s", user)
    data = cur.fetchall()
    # print(data)
    conv_list = []

    for j in range(len(data)):
        conv = json.loads(data[j]['dataz'])
        conv = conv.replace("'", '"')
        conv2 = json.loads(conv)
        conv_list.append(conv2)

    quiz_names = []
    emails = []
    emails_str = []
    for k in conv_list:
        for l in k.keys():
            if k[l] == ['Submit']:
                quiz_names.append(l)
            if l == 'email':
                print(k[l])
                email_str = ''
                for item_idx in range(1, len(k[l])):
                    email_str += k[l][item_idx] + ';'
                    emails.append(k[l][item_idx])
                emails_str.append(email_str)
    print(emails)
    print(emails_str)
    return render_template('send_quizzes.html', quiz_names=quiz_names, emails=emails_str)

@app.route("/update", methods=['POST', 'GET'])
@is_logged_in
def update():
    if request.method == 'POST':
        result = request.form
        Table = []
        for key, value in result.items():
            temp = []
            temp.extend([key,value])
            Table.append(temp)
        q = request.form
        '''print(q)'''
        json_stuff = (q.to_dict(flat=False))
        qname = None
        for i in json_stuff.keys():
            # print(i)
            if json_stuff[i] == ['Submit']:

                qname = i
        # print(qname)
        json_data = str(json_stuff)
        '''convert to json string double quotes'''
        json_string = json.dumps(json_data)
        '''open database connnection, add user defined quiz into database and close connection'''
        cur=mysql.connection.cursor()
        '''global variable which holds UID'''
        x = session["UID"]

        cur.execute("UPDATE quizinformation SET dataz = %s WHERE UID = %s AND qname = %s", (json_string, x, qname))

        mysql.connection.commit()
        cur.close()

        """to display in preview.html"""

        return redirect('dashboard')

@app.route("/view_results/<UID>", methods=['GET'])
@is_logged_in
def view_results(UID):
    user = str(session["UID"])
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM quizinformation WHERE UID = %s", user)
    data = cur.fetchall()
    conv_list = []

    for j in range(len(data)):
        conv = json.loads(data[j]['dataz'])
        conv = conv.replace("'", '"')
        conv2 = json.loads(conv)
        conv_list.append(conv2)

    names = []
    URL_names = []
    for k in conv_list:
        for l in k.keys():
            if k[l] == ['Submit']:
                names.append(l)
                URL = l.replace(" ", '_')
                URL_names.append(URL)
    return render_template('view_results.html', names=names, UID=user, URL=URL_names)

@app.route("/compare_results/<UID>/<qname>", methods=['GET'])
@is_logged_in
def compare_results(UID, qname):
    qname = qname.replace('_', ' ')
    user = str(session["UID"])
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM quizresults WHERE UID = %s AND qname = %s", [user, qname])
    data = cur.fetchall()
    user_and_score = []
    for i in range(len(data)):
        user_and_score.append([data[i]['candidate_email'],data[i]['score']])
    user_and_score = sorted(user_and_score, key=lambda t: t[1],reverse=True)



    return render_template('compare_results.html', scores=user_and_score, qname=qname)




@app.route("/help", methods=['POST', 'GET'])
@is_logged_in
def help():
    return render_template('help.html')



@app.route("/contact", methods=['POST', 'GET'])
@is_logged_in
def contact():
    return render_template('contact.html')


@app.route("/about")
@is_logged_in
def about():
    return render_template('about.html')


@app.route("/")
def home():
    user = session.get('user')
    if user:
        # print(json.dumps(user["userinfo"], sort_keys=False, indent=4))
        # return "Hello World, " + user["userinfo"]["name"] + "!"
        flash("Hello, " + user["userinfo"]["name"] + "!", 'success')
    else:
        # return "Hello World, Mrs. Anonymous!"
        flash("Hello, Mrs. Anonymous!",'success')
    return redirect('dashboard')


@app.route("/public")
def public():
    return "A public endpoint"


@app.route("/private")
@is_logged_in
def private():
    return "A private endpoint"


@app.route("/login")
def login():
    r_args = request.args
    url_from = r_args.get('from')
    if(url_from is None):
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for("callback", _external=True)
        )
    else:
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for("callback", _external=True) + '?to=' + url_from
        )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    cur = mysql.connection.cursor()
    cur.execute("select * from users where EMAIL=%s", [token['userinfo']['email']])
    data = cur.fetchone()
    global x
    if data:
        session['logged_in'] = True
        session['username'] = data["UNAME"]
        x = (data["UID"])
        session["UID"] = data["UID"]
    else:
        cur = mysql.connection.cursor()
        cur.execute("insert into users(UNAME,UPASS,EMAIL) values(%s,%s,%s)", (token['userinfo']['name'], '', token['userinfo']['email']))
        mysql.connection.commit()
        cur.execute("select * from users where EMAIL=%s", [token['userinfo']['email']])
        data = cur.fetchone()
        x = (data["UID"])
        session["UID"] = data["UID"]
        cur.close()
    r_args = request.args
    url_to = r_args.get('to')
    if url_to is None:
        return redirect("/")
    else:
        return redirect(urllib.parse.unquote(url_to))


# logout
# @app.route("/logout")
# def logout():
#     session.clear()
#     flash('You are now logged out', 'success')
#     return redirect(url_for('login'))
#
@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


def add_key(dic,key,value):
  if key in dic:
    dic[key]+=value
  else:
    dic[key]=value


# quiz submission and score calculation
@app.route("/quiz_submission", methods=['POST', 'GET'])
def quiz_submission():
    if request.method == 'POST':
        result = request.form
        Table = []
        for key, value in result.items():
            temp = []
            temp.extend([key,value])
            Table.append(temp)
        q = request.form
        '''print(q)'''
        json_stuff= (q.to_dict(flat=False))
        qname = None
        for i in json_stuff.keys():
            if json_stuff[i] == ['Submit']:
                qname = i
        json_data = str(json_stuff)
        '''convert to json string double quotes'''
        json_string = json.dumps(json_data)
        '''open database connnection, get the quiz answers'''
        cur=mysql.connection.cursor()
        UID = q["quiz_sender"]
        qname = q['quiz_name']
        cur.execute("select * from quizinformation where UID=%s and qname=%s",
                    [UID, qname])
        mysql.connection.commit()
        data = cur.fetchall()

        # anses={}
        anses = json.loads(
            json.loads(data[0]['dataz']).replace("'", '"')
        )
        # print(anses)
        choices={}
        for key,value in q.items():
          if key[0]=='R' and value=='on':
            choice = [int(x) for x in key[2::].split('_')]
            add_key(choices,'A_' + str(choice[0]),[choice[1]])
        choices_str={}
        for key,value in choices.items():
          choices_str[key]=str(value[0])
          for ii in range(1,len(value)):
            add_key(choices_str,key,';'+str(value[ii]))
        # print(choices,choices_str)
        # print(q)
        score = 0
        for key,value in choices_str.items():
          if key in anses:
            # print("choice:",value)
            # print("anwser:",anses[key][0])
            # print(value==anses[key][0])
            if(value==anses[key][0]):
              score += 1
        print(score)
        cur.execute("insert into quizresults(UID, qname, candidate_email, score, dataz) values(%s,%s,%s,%s,%s)",
                    (UID,qname,q.get('candidate'),score,json_string))
        mysql.connection.commit()
        cur.close()
        return "Thank you for your participation!"

@app.route("/quiz4candidate", methods=['POST', 'GET'])
def quiz4candidate():
    if request.method == 'GET':
        r_args = request.args
        candidate_info = r_args.get('candidate_info')
        if candidate_info is None:
            return "No candidate_info!"
        else:
            try:
                candidate_info = urllib.parse.unquote(candidate_info)
                candidate_info_data = jwt.decode(candidate_info, env.get('JWT_SECRET'), algorithms=['HS256'])
            except Exception as ex:
                print(ex)
                return "Link expired!"
            qname = candidate_info_data.get('quiz_name')
            UID = candidate_info_data.get('UID')
            candidate_email = candidate_info_data.get('candidate_email')
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM quizinformation WHERE UID=%s and qname=%s",
                        [UID, qname])
            data = cur.fetchall()
            quiz_content = json.loads(
                json.loads(data[0]['dataz']).replace("'", '"')
            )
            #the time for the quiz
            time_as_list = quiz_content['minutes']
            time_as_str = ''.join(time_as_list)
            time_no_brackets = time_as_str.strip("['']")
            quiz_time = int(time_no_brackets)
            # return jsonify(quiz_content)
            return render_template("quiz4candidate.html",
                                   quiz_content=quiz_content,
                                   quiz_name=qname,
                                   UID=UID,
                                   candidate_email=candidate_email,
                                   jwt=candidate_info,
                                   quiz_time=quiz_time
                                   )
    else:
        emails = request.form["email"].split(';')
        exp = request.form.get('exp')
        quiz_name = request.form.get('quiz_name')
        if exp is None:
            exp = 30
        else:
            exp = int(exp)
        # print('Cookies\n')
        # print(request.cookies)
        # print('Session\n')
        # print(session)
        user = session.get('user')
        if user:
            userinfo = user.get('userinfo')
            sender_name = userinfo.get('name')
        else:
            sender_name = 'Online Quiz'
        if len(emails) > 1:
            with mail.connect() as conn:
                for email in emails:
                    if email:
                        token = jwt.encode({'candidate_email': email,
                                            'UID': session['UID'],
                                            'quiz_name': quiz_name,
                                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=exp)
                                            },
                                           env.get("JWT_SECRET"))
                        msg = Message("Quiz Link from {}".format(sender_name), sender = env.get("QUIZ_EMAIL"), recipients = [email])
                        msg.body = url_for('quiz4candidate', _external=True) + '?candidate_info=' + urllib.parse.quote(token,safe="")
                        conn.send(msg)
                        time.sleep(60)
        else:
            token = jwt.encode({'candidate_email': emails[0],
                                'UID': session['UID'],
                                'quiz_name': quiz_name,
                                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=exp)
                                },
                               env.get("JWT_SECRET"))
            msg = Message("Quiz Link from {}".format(sender_name), sender = env.get("QUIZ_EMAIL"), recipients = [emails[0]])
            msg.body = url_for('quiz4candidate', _external=True) + '?candidate_info=' + urllib.parse.quote(token,safe="")
            mail.send(msg)
        return jsonify({'email': emails})



@app.route("/jwtgen", methods=['POST', 'GET'])
def jwtgen():
    if request.method == 'POST':
        email = request.form["email"]
        token = jwt.encode({'candidate_email': email,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)},
                           env.get("JWT_SECRET"))
        return jsonify({'token': token,
                        'email': urllib.parse.quote(email,safe=""),
                        'to_en': urllib.parse.quote(token,safe="")})
    else:
        r_args = request.args
        email = r_args.get('email')
        # print(session)
        # print(request.cookies)
        r = requests.post(url_for('quiz4candidate', _external=True), data={'email': email},cookies=request.cookies)
        # print(r.json())
        return '{:d}'.format(r.status_code)


if __name__ == '__main__':
    # app.secret_key='secret123'
    app.run(debug=True)
