from flask import Flask, request, url_for, redirect
from flask.globals import session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask.templating import render_template
import bcrypt
import os , datetime
from sqlalchemy.orm import backref
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads/'
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:musa@localhost/akiba"

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class UserAccount(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    phone = db.Column(db.String(100))
    pin = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))
    account_balance = db.Column(db.Float, default=0.0)
    float_balance = db.Column(db.Integer)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), default=3)
    profile_pic = db.Column(db.String(100))
    notification = db.Column(db.String(100))

    def __init__(self, id, firstname, lastname, username, password, phone, pin, profile_pic, notification):
        self.id = id
        self.firstname = firstname
        self.lastname = lastname
        self.username = username
        self.password = password
        self.phone = phone
        self.pin = pin
        self.profile_pic = profile_pic
        self.notification = notification

class RoleAccount(db.Model):   
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50))
    users = db.relationship('UserAccount', backref='role', lazy=True)


class TransactionAccount(db.Model):
    __tablename__ = "transactions"

    ref_no = db.Column(db.String(15), primary_key=True)
    id_no = db.Column(db.Integer)
    date = db.Column(db.String(100))
    deposit = db.Column(db.String(100))
    withdrawal = db.Column(db.String(100))
    status = db.Column(db.String(100))

    def __init__(self, ref_no, id_no, date, deposit, withdrawal, status):
        self.ref_no = ref_no
        self.id_no = id_no
        self.date = date
        self.deposit = deposit
        self.withdrawal = withdrawal
        self.status = status


class DepositsAccount(db.Model):
    __tablename__ = "deposits"

    ref_no = db.Column(db.String(15), primary_key=True)
    id_no = db.Column(db.Integer)
    date = db.Column(db.String(100))
    amount = db.Column(db.String(100))

    def __init__(self, ref_no, id_no, date, amount):
        self.ref_no = ref_no
        self.id_no = id_no
        self.date = date
        self.amount = amount

class InactiveUserAccount(db.Model):   
    __tablename__ = "inactive_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))

    def __init__(self, id, username):
        self.id = id
        self.username = username
    

@app.route('/')
def index():
  return render_template('index.html')

@app.route('/admin/system_members')
def ViewUsers():
    if 'id' in session and 'role' in session:
        role_id = session.get('role')
        if role_id == 1:
            role_id = 3
            users = UserAccount.query.filter_by(role_id=role_id).all()
            return render_template('users.html', users = users)
    return redirect(url_for('Login'))


@app.route('/admin/system_agents')
def ViewAgents():
    if 'id' in session and 'role' in session:
        role_id = session.get('role')
        if role_id == 1:
            role_id = 2
            users = UserAccount.query.filter_by(role_id=role_id).all()
            return render_template('agents.html', users = users)
    return redirect(url_for('Login'))



@app.route('/register', methods = ["POST","GET"])
def Register():
    users = UserAccount.query.all()

    # getting form details from registration form
    if request.method == "POST":
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        id = request.form.get('id_no')
        phone = request.form.get('phone')
        pin = request.form.get('pin')
        confirm_pin = request.form.get('confirm_pin')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirm')

    
        # get/check the entered user_id no and username in the users' table(database) (if any)
        user_ID = UserAccount.query.filter_by(id=id).first()
        new_user = UserAccount.query.filter_by(username=username).first()

        # check if the user_id and username are already used
        if user_ID is None:
            if new_user is not None:
                error_msg = "The username you entered is already taken!"
                error_msg2 = "Try again and use another username."
                return render_template("register_error2.html", username_error = error_msg, username_error2 = error_msg2)   
        else:
            idError = "The ID number you entered already exists!"
            idError2 = "Try again with another ID number."
            return render_template("register_error.html", id_error = idError, id_error2 = idError2)
        
        
        # encrypting the password and pin using hash function
        if confirm == password and pin == confirm_pin:
            encrpted_pass =  bcrypt.hashpw(password.encode(), bcrypt.gensalt(14))
            encrpted_pin = bcrypt.hashpw(pin.encode(), bcrypt.gensalt(14))
            registered_user = UserAccount(id,firstname,lastname,username,encrpted_pass.decode(),phone,encrpted_pin.decode(),profile_pic='default.png',notification='0')

        # add the details in the database
        db.session.add(registered_user)
        db.session.commit()
        return render_template('register_success.html')
    return render_template('register.html', users_list = users)
    

@app.route('/login', methods=['POST','GET'])
def Login():

    # getting form details from login form
    if request.method=="POST":
        username=request.form.get('username')
        password=request.form.get('password')

        # get/check the person with the entered username in the database
        inactive_user = InactiveUserAccount.query.filter_by(username=username).first()
        if inactive_user:
            return "Sorry your account has been deactivated! Please contact the administrator."
        else:
            current_user = UserAccount.query.filter_by(username=username).first()
            user_role = current_user.role
            my_role = user_role.role_name

            # check the existence of the person in the database
            # if current_user is not None:(opposite statement)
            if current_user is None:
                return render_template("login_error.html")
            else:
                # get the password and encrypt it and check the match with the one encrypted in the database(will be success or error)
                result = bcrypt.checkpw(password.encode(), current_user.password.encode())
                if result:
                    session['id'] = current_user.id
                    session['role'] = current_user.role_id
                    # check if he/she is the admin 
                    if current_user.role_id == 1:
                        user_msg = current_user.notification
                        if user_msg == '0':
                            no_msg = "no notification"
                            return render_template("admin_home.html",user = current_user, my_role=my_role, no_msg=no_msg)
                        else:
                            notify_msg = user_msg
                            return render_template("admin_home.html",user = current_user, my_role=my_role, notify_msg=notify_msg)
                    else:
                        user_msg = current_user.notification
                        if user_msg == '0':
                            no_msg = "no notification"
                            return render_template("user_home.html",user = current_user, my_role=my_role, no_msg=no_msg)
                        else:
                            notify_msg = user_msg
                            return render_template("user_home.html",user = current_user, my_role=my_role, notify_msg=notify_msg)
                else:
                    return render_template("login_error.html")
    return render_template('login.html')



@app.route('/reset', methods = ['POST','GET'])
def Reset():
    if request.method=="POST":
        id=request.form.get('id_no')
        username=request.form.get('username')

        current_user = UserAccount.query.filter_by(id=id).first()
        if current_user is not None:
            correct_username = current_user.username
            if username == correct_username:
                param = datetime.datetime.now().strftime("%S")
                new_pass = '{}Q{}kX'.format(current_user.firstname,param)
                encrpted_pass =  bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt(14))
                current_user.password = encrpted_pass.decode()
                db.session.add(current_user)
                db.session.commit()
                return "Your password has been reset. Your new password is <u><b>{}</b></u> <br> Login and change the password for security purposes.".format(new_pass)
            else:
                msg2 = "Enter a valid username. If you forgot your username contact the Admin!"
                return render_template('reset.html', msg2=msg2)
        else:
            msg= "You have entered unregistered ID!"
            return render_template('reset.html',msg=msg)
    return render_template('reset.html')

@app.route('/logout')
def logout():
    if 'id' in session:
        session.pop('id', None)
        return redirect(url_for('index'))
    return redirect(url_for('Login'))


@app.route('/home')
def Home():
    if 'id' in session and 'role' in session:
        user_id = session.get('id')
        role_id = session.get('role')
        if role_id != 1:
            current_user = UserAccount.query.get(user_id)
            user_role = UserAccount.query.get(user_id).role
            my_role = user_role.role_name
            user_msg = current_user.notification
            if user_msg == '0':
                no_msg = "no notification"
                return render_template("user_home.html",user = current_user, my_role=my_role, no_msg=no_msg)
            else:
                notify_msg = user_msg
                return render_template("user_home.html",user = current_user, my_role=my_role, notify_msg=notify_msg)
    return redirect(url_for('Login'))

@app.route('/admin')
def Admin():
    if 'id' in session and 'role' in session:
        user_id = session.get('id')
        role_id = session.get('role')
        if role_id == 1:
            current_user = UserAccount.query.get(user_id)
            user_role = UserAccount.query.get(user_id).role
            my_role = user_role.role_name
            user_msg = current_user.notification
            if user_msg == '0':
                no_msg = "no notification"
                return render_template("admin_home.html",user = current_user, my_role=my_role, no_msg=no_msg)
            else:
                notify_msg = user_msg
                return render_template("admin_home.html",user = current_user, my_role=my_role, notify_msg=notify_msg)
    return redirect(url_for('Login'))


@app.route('/admin/account')
def AdminAccount():
    if 'id' in session and 'role' in session:
        role_id = session.get('role')
        if role_id == 1:
            return render_template("admin.html")
    return redirect(url_for('Login'))


@app.route('/home/account')
def Account():
    if 'id' in session and 'role' in session:
        role_id = session.get('role')
        if role_id == 2:
            return render_template("account.html")
        elif role_id == 3:
            return render_template('user_account.html')
    return redirect(url_for('Login'))


@app.route('/userDetails')
def UserEditing():
    if 'id' in session and 'role' in session:
        user_id = session.get('id')
        role_id = session.get('role')
        if role_id != 1:
            current_user = UserAccount.query.get(user_id)
            return render_template("user_details.html", user = current_user)
        else:
            current_user = UserAccount.query.get(user_id)
            return render_template("admin_details.html", user = current_user)
    return redirect(url_for('Login'))


@app.route('/userDetails/editData', methods = ['POST','GET'])
def UserSaving():
    if request.method == "POST":
        if 'id' in session:
            user_id = session.get('id')
            name1 = request.form.get('name1')
            name2 = request.form.get('name2')
            name3 = request.form.get('name3')
            name4 = request.form.get('name4')
            current_user = UserAccount.query.get(user_id)

            current_user.username = name1
            current_user.firstname = name2
            current_user.lastname = name3
            current_user.phone = name4
            db.session.add(current_user)
            db.session.commit()
                                
            one_user = UserAccount.query.get(user_id)
            role_id = session.get('role')
            if role_id != 1:
                return render_template("user_details.html", user = one_user)
            else:
                return render_template("admin_details.html", user = one_user)
    return redirect(url_for('Login'))


@app.route('/userDetails/editPhoto', methods = ['POST','GET'])
def PhotoUpload():
    if request.method == "POST":
        if 'id' in session:
            user_id = session.get('id')
            pic = request.files['pic']

            user = UserAccount.query.get(user_id)
            filename = secure_filename(pic.filename)
            pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            user.profile_pic = filename
            db.session.add(user)
            db.session.commit()

            one_user = UserAccount.query.get(user_id)
            role_id = session.get('role')
            if role_id != 1:
                return render_template("user_details.html", user= one_user)
            else:
                return render_template("admin_details.html", user= one_user)
    return redirect(url_for('Login'))


@app.route('/account/check_balance', methods=['POST','GET'])
def CheckBalance():
    if request.method == "POST":
        if 'id' in session and 'role' in session:
            user_id = session.get('id')
            id = int(request.form.get('id_no'))
            pin = request.form.get('pin_no')
            user_role = session.get('role')
            if user_id == id:
                current_user = UserAccount.query.filter_by(id=id).first()
                if current_user is not None:
                    result = bcrypt.checkpw(pin.encode(), current_user.pin.encode())
                    if result:
                        if current_user.role_id == 3:
                            time = datetime.datetime.now().strftime("%d/%m/%Y at %I:%M %p")
                            return render_template('user_balance.html', user = current_user, the_time = time)
                        elif current_user.role_id == 2:
                            time = datetime.datetime.now().strftime("%d/%m/%Y at %I:%M %p")
                            return render_template('user_balance.html', agent = current_user, the_time = time)
                        else:
                            time = datetime.datetime.now().strftime("%d/%m/%Y at %I:%M %p")
                            return render_template('admin_balance.html', admin = current_user, the_time = time)
                    else:
                        if current_user.role_id != 1:
                            pin_mismatch = "Sorry! You have entered wrong PIN. Try again."
                            return render_template('user_balance.html', errored_pin_msg = pin_mismatch)
                        else:
                            pin_mismatch = "Sorry! You have entered wrong PIN. Try again."
                            return render_template('admin_balance.html', errored_pin_msg = pin_mismatch)
                else:
                    if current_user.role_id != 1:
                        not_found_msg = "Invalid ID! Please confirm your ID number and try again."
                        return render_template('user_balance.html', not_found = not_found_msg )
                    else:
                        not_found_msg = "Invalid ID! Please confirm your ID number and try again."
                        return render_template('admin_balance.html', not_found = not_found_msg)
            else:
                if user_role != 1:
                    not_found_msg = "Invalid ID! Please confirm your ID number and try again."
                    return render_template('user_balance.html', not_found = not_found_msg )
                else:
                    not_found_msg = "Invalid ID! Please confirm your ID number and try again."
                    return render_template('admin_balance.html', not_found = not_found_msg)
    return redirect(url_for('Login'))


@app.route('/account/deposit', methods= ['GET','POST'])
def Deposit():
    # a varible to get agent
    if request.method == 'POST':
        if 'id' in session:
            agent_id = request.form.get('agent_id') 
            agent_role = session.get('role') 

            # variable to store the agent by (get) to obtain one
            # to get more than one agent use (filter_by()) 
            agent = UserAccount.query.get(agent_id)

            # variable to define the agent_pin and the amount to deposit
            pin = request.form.get('pin_no')
            amount = int(request.form.get('amount'))

            if agent is not None:
                if agent.role_id != 3:
                    result = bcrypt.checkpw(pin.encode(), agent.pin.encode())
                    if result:
                        # to check if the float is enough to deposit the amount
                        if agent.float_balance >= amount:

                            # go find a user
                            user_id = request.form.get('user_id')
                            user = UserAccount.query.get(user_id)
                            if user:
                                # deposit the amount to their account and update agent float_balance
                                user.account_balance += amount
                                db.session.add(user)
                                db.session.commit()

                                agent.float_balance -= amount
                                db.session.add(agent)
                                db.session.commit()
                                
                                one_user = UserAccount.query.get(user_id)
                                time = datetime.datetime.now().strftime("%d/%m/%Y at %I:%M %p")
                                ref = datetime.datetime.now().strftime("%H%M%S")
                                refNo = 'TX{}'.format(ref)
                                theID = user.id
                                theAgent = agent.id
                                new_balance = one_user.account_balance
                                notification="You have deposited Ksh. {} via agent ID {}. New balance is {}".format(amount,theAgent,new_balance)
                                one_user.notification = notification
                                db.session.add(one_user)
                                db.session.commit()

                                transaction = TransactionAccount(refNo,theID,time,amount,withdrawal='',status='SUCCESS')
                                db.session.add(transaction)
                                db.session.commit()

                                deposits = DepositsAccount(refNo,theID,time,amount)
                                db.session.add(deposits)
                                db.session.commit()
                                if agent_role == 2:
                                    return render_template('user_balance.html', the_user=one_user, time=time, amount=amount, refNo=refNo, theID=theID, theAgent=theAgent)
                                else:
                                   return render_template('admin_balance.html', the_user=one_user, time=time, amount=amount, refNo=refNo, theID=theID, theAdmin=theAgent) 
                            else:
                                if agent_role == 2:
                                    no_user = "Invalid user ID! Please confirm the user ID number and try again."
                                    return render_template('user_balance.html', no_user_found = no_user)
                                else:
                                    no_user = "Invalid user ID! Please confirm the user ID number and try again."
                                    return render_template('admin_balance.html', no_user_found = no_user)
                        else:
                            # the agent account has no enough money to deposit
                            if agent_role == 2:
                                no_float_msg= 'Sorry! You have no enough funds to deposit Ksh {}.'.format(amount)
                                return render_template("user_balance.html", no_float = no_float_msg)
                            else:
                                no_float_msg= 'Sorry! You have no enough funds to deposit Ksh {}.'.format(amount)
                                return render_template("admin_balance.html", no_float = no_float_msg)
                    else:
                        if agent_role == 2:
                            agent_pin_error = "Sorry! You have entered wrong PIN. Try again."
                            return render_template('user_balance.html', agent_pinerror = agent_pin_error)
                        else:
                            admin_pin_error = "Sorry! You have entered wrong PIN. Try again."
                            return render_template('admin_balance.html', admin_pinerror = admin_pin_error)
                else:
                    if agent_role == 2:
                        no_agent = "Agent not found! Confirm your ID number and try again."
                        return render_template('user_balance.html', no_agent_found = no_agent)
                    else:
                        no_admin = "Admin not found! Confirm your ID number and try again."
                        return render_template('admin_balance.html', no_admin_found = no_admin)    
            else:
                if agent_role == 2:
                    no_agent = "Agent not found! Confirm your ID number and try again."
                    return render_template('user_balance.html', no_agent_found = no_agent)
                else:
                    no_admin = "Admin not found! Confirm your ID number and try again."
                    return render_template('admin_balance.html', no_admin_found = no_admin)
    return redirect(url_for('Login'))


@app.route('/account/withdraw', methods= ['GET','POST'])
def Withdraw():
    if request.method == 'POST':
        if 'id' in session:
            logged_user = session.get('id')
            user_role = session.get('role')
            agent_id = request.form.get('agent_id')
            user_id = int(request.form.get('user_id'))
            pin = request.form.get('pin_no')
            amount = int(request.form.get('amount'))
            agent = UserAccount.query.get(agent_id)

            if agent is not None:
                if agent.role_id == 2:
                    if logged_user == user_id:
                        user = UserAccount.query.get(user_id)
                        if user is not None:
                            result = bcrypt.checkpw(pin.encode(), user.pin.encode()) 
                            if result:
                                if user.account_balance > amount:
                                    user.account_balance = user.account_balance - (amount + (0.03*amount))
                                    user.account_balance = "{:.2f}".format(user.account_balance)
                                    db.session.add(user)
                                    db.session.commit()

                                    agent.float_balance += amount
                                    db.session.add(agent)
                                    db.session.commit()

                                    one_user = UserAccount.query.get(user_id)
                                    time = datetime.datetime.now().strftime("%d/%m/%Y at %I:%M %p")
                                    new_balance = one_user.account_balance
                                    theID = user.id
                                    theAgent = agent.id
                                    ref = datetime.datetime.now().strftime("%H%M%S")
                                    refNo = 'TX{}'.format(ref)
                                    transaction = TransactionAccount(refNo,theID,time,deposit='',withdrawal=amount,status='SUCCESS')
                                    db.session.add(transaction)
                                    db.session.commit()
                                    if user_role != 1:
                                        return render_template('user_balance.html', that_user=one_user, time=time, amount=amount, new_balance=new_balance, refNo=refNo, theID=theID, theAgent=theAgent)
                                    else:
                                        return render_template('admin_balance.html', that_user=one_user, time=time, amount=amount, refNo=refNo, new_balance=new_balance, theID=theID, theAdmin=theAgent)
                                else:
                                    if user_role != 1:
                                        withdraw_error_message = 'Sorry! You have insufficient balance to withdraw such amount.'
                                        return render_template('user_balance.html', withdraw_error_msg = withdraw_error_message) 
                                    else:
                                        withdraw_error_message = 'Sorry! You have insufficient balance to withdraw such amount'
                                        return render_template('admin_balance.html', withdraw_error_msg = withdraw_error_message) 
                            else:
                                if user_role != 1:
                                    pin_occured_err = "Sorry! You have entered wrong PIN. Try again"
                                    return render_template('user_balance.html', pin_err = pin_occured_err) 
                                else:
                                    pin_occured_err = "Sorry! You have entered wrong PIN. Try again"
                                    return render_template('admin_balance.html', pin_err = pin_occured_err) 
                        else:
                            if user_role != 1:
                                userID_error = "Invalid ID! Please confirm your ID number and try again."
                                return render_template('user_balance.html', user_id_error = userID_error)
                            else:
                                userID_error = "Invalid ID! Please confirm your ID number and try again."
                                return render_template('admin_balance.html', user_id_error = userID_error)
                    else:
                        if user_role != 1:
                            userID_error = "Invalid ID! Please confirm your ID number and try again."
                            return render_template('user_balance.html', user_id_error = userID_error)
                        else:
                            userID_error = "Invalid ID! Please confirm your ID number and try again."
                            return render_template('admin_balance.html', user_id_error = userID_error)
                else:
                    if user_role != 1:
                        agentID_error = "Agent not found! Confirm the Agent ID and try again."
                        return render_template('user_balance.html', agentID_err = agentID_error)
                    else:
                        agentID_error = "Agent not found! Confirm the Agent ID and try again."
                        return render_template('admin_balance.html', agentID_err = agentID_error)
            else:
                if user_role != 1:
                    agentID_error = "Agent not found! Confirm the Agent ID and try again."
                    return render_template('user_balance.html', agentID_err = agentID_error)
                else:
                    agentID_error = "Agent not found! Confirm the Agent ID and try again."
                    return render_template('admin_balance.html', agentID_err = agentID_error)
    return redirect(url_for('Login'))


@app.route('/admin/system_info')
def SystemInfo():
    if 'id' in session and 'role' in session:
        role_id = session.get('role')
        if role_id == 1:
            return render_template('system_info.html')
    return redirect(url_for('Login'))


@app.route('/account/statement', methods =['POST','GET'])
def ViewStatement():
    if request.method == 'POST':
        id = int(request.form.get('id_no'))
        pin = request.form.get('pin_no')
        if 'id' in session and 'role' in session:
            role_id = session.get('role')
            user_id = session.get('id')
            if id == user_id:
                user = UserAccount.query.get(user_id)
                result = bcrypt.checkpw(pin.encode(), user.pin.encode())
                if result:
                    if role_id != 1:
                        transactions = TransactionAccount.query.filter_by(id_no=user_id).all()
                        if(len(transactions)< 1):
                            no_tx = "You have zero transaction!"
                            return render_template('account_statement.html', no_tx = no_tx)
                        download = "download"
                        return render_template('account_statement.html', transactions = transactions, download=download)
                    else:
                        transactions = TransactionAccount.query.all()
                        if(len(transactions)< 1):
                            no_tx = "You have zero transaction!"
                            return render_template('admin_statement.html', no_tx = no_tx)
                        download = "download"
                        return render_template('admin_statement.html', transactions = transactions, download=download)
                else:
                    return "You have entered wrong PIN try again later"
            else:
                return "You have entered wrong ID try again later"
    return redirect(url_for('Login'))


@app.route('/account/deposits', methods =['POST','GET'])
def ViewDeposit():
    if request.method == 'POST':
        user_depo = request.form.get('depo')
        if 'id' in session and 'role' in session:
            role_id = session.get('role')
            user_id = session.get('id') 
            if role_id != 1:
                deposits = DepositsAccount.query.filter_by(id_no=user_id).all()
                if(len(deposits)< 1):
                    no_dp = "You have zero deposit!"
                    return render_template('deposits.html', no_dp = no_dp)
                return render_template('deposits.html', deposits = deposits)
    return redirect(url_for('Login'))


@app.route('/notificationViewed', methods = ['POST','GET'])
def ChangeNotification():
    if request.method == "POST":
        if 'id' in session:
            user_id = session.get('id')
            notify = request.form.get('notify')
            notify = "0"
            current_user = UserAccount.query.get(user_id)

            current_user.notification = notify
            db.session.add(current_user)
            db.session.commit()
                                
            user_role = UserAccount.query.get(user_id).role
            my_role = user_role.role_name
            role_id = session.get('role')
            if role_id != 1:
                no_msg = "no notification"
                return render_template("user_home.html",user = current_user, my_role=my_role, no_msg=no_msg)
            else:
                no_msg = "no notification"
                return render_template("admin_home.html",user = current_user, my_role=my_role, no_msg=no_msg)
    return redirect(url_for('Login'))


@app.route('/admin/manageUser', methods= ['POST','GET'])
def manageUser():
    if 'id' in session:
        if request.method == "POST":
            id = request.form.get('id')
            current_user = UserAccount.query.get(id)
            inactive_user = InactiveUserAccount.query.get(id)
            if inactive_user:
                if current_user.role_id == 2:
                    return render_template('manage_user.html', inactive_agent=current_user)
                else:
                    return render_template('manage_user.html', inactive_user=current_user) 
            else:
                if current_user.role_id == 2:
                    return render_template('manage_user.html', agent=current_user)
                else:
                    return render_template('manage_user.html', user=current_user)               
    return redirect(url_for('Login'))


@app.route('/admin/deactivateUser', methods= ['POST','GET'])
def deactivateUser():
    if 'id' in session:
        if request.method == "POST":
            id = request.form.get('id')
            current_user = UserAccount.query.get(id)
            username = current_user.username
            user_account = InactiveUserAccount(id,username)
            db.session.add(user_account)
            db.session.commit()
            return "User's account with ID:{} has been deactivated.".format(id)              
    return redirect(url_for('Login'))


@app.route('/admin/activateUser', methods= ['POST','GET'])
def activateUser():
    if 'id' in session:
        if request.method == "POST":
            id = request.form.get('id')
            user_id = id
            active_user = InactiveUserAccount.query.filter_by(id=user_id).one()
            db.session.delete(active_user)
            db.session.commit()
            return "User's account with ID:{} has been activated.".format(id)              
    return redirect(url_for('Login'))


@app.route('/admin/updateFloat', methods= ['POST','GET'])
def updateFloat():
    if 'id' in session:
        if request.method == "POST":
            id = request.form.get('id')
            current_user = UserAccount.query.get(id)
            return render_template('manage_user.html', agent_float=current_user)              
    return redirect(url_for('Login'))


@app.route('/account/edit_pass')
def EditPass():
    if 'id' in session:
      return render_template('edit_pass.html')
    return redirect(url_for('Login'))
    
    
@app.route('/account/change_pass', methods= ['POST','GET'])
def changePass():
    if request.method == "POST":
        if 'id' in session:
            user_id = session.get('id')
            passwd = request.form.get('password')

            current_user = UserAccount.query.get(user_id)
            result = bcrypt.checkpw(passwd.encode(), current_user.password.encode())
            if result:
                return render_template('change_pass.html')
            msg= "You have entered wrong Password!"
            return render_template('edit_pass.html', msg=msg)
    return redirect(url_for('Login'))
    

@app.route('/account/pass_reset', methods= ['POST','GET'])
def PassChanged():
    if request.method == "POST":
        if 'id' in session:
            user_id = session.get('id')
            passwd = request.form.get('password')
            confirm = request.form.get('confirm')

            current_user = UserAccount.query.get(user_id)
            if passwd == confirm:
                encrpted_pass =  bcrypt.hashpw(passwd.encode(), bcrypt.gensalt(14))
                current_user.password = encrpted_pass.decode()
                db.session.add(current_user)
                db.session.commit()
                return "Your Password has been reset successfully. You can now login with your new Password."
            msg2= "Password does not match!"
            return render_template('change_pass.html', msg2=msg2)
    return redirect(url_for('Login'))


@app.route('/account/edit_pin')
def EditPin():
    if 'id' in session:
        return render_template('edit_pin.html')
    return redirect(url_for('Login'))
    
    
@app.route('/account/change_pin', methods= ['POST','GET'])
def changePin():
    if request.method == "POST":
        if 'id' in session:
            user_id = session.get('id')
            pin = request.form.get('pin')

            current_user = UserAccount.query.get(user_id)
            result = bcrypt.checkpw(pin.encode(), current_user.pin.encode())
            if result:
                return render_template('change_pin.html')
            msg= "You have entered wrong PIN!"
            return render_template('edit_pin.html', msg=msg)
    return redirect(url_for('Login'))
    

@app.route('/account/pin_reset', methods= ['POST','GET'])
def PinChanged():
    if request.method == "POST":
        if 'id' in session:
            user_id = session.get('id')
            pin = request.form.get('pin')
            confirm = request.form.get('confirm')

            current_user = UserAccount.query.get(user_id)
            if pin == confirm:
                encrpted_pin =  bcrypt.hashpw(pin.encode(), bcrypt.gensalt(14))
                current_user.pin = encrpted_pin.decode()
                db.session.add(current_user)
                db.session.commit()
                return "Your PIN has been reset successfully. You can now transact with your new PIN."
            msg2= "PIN does not match!"
            return render_template('change_pin.html', msg2=msg2)
    return redirect(url_for('Login'))

    

if __name__ == "__main__":
    app.run(host="0.0.0.0")