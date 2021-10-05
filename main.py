from flask import Flask, jsonify, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, current
from flask.templating import render_template
import bcrypt
import os

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from sqlalchemy.orm import backref
import datetime

from werkzeug.utils import secure_filename


app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads/'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config["JWT_SECRET_KEY"] = "super-secret" 
jwt = JWTManager(app)
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

    def __init__(self, id, firstname, lastname, username, password, phone, pin, profile_pic):
        self.id = id
        self.firstname = firstname
        self.lastname = lastname
        self.username = username
        self.password = password
        self.phone = phone
        self.pin = pin
        self.profile_pic = profile_pic


class RoleAccount(db.Model):  
    
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50))
    users = db.relationship('UserAccount', backref='role', lazy=True)
    

@app.route('/')
def index():
  return render_template('index.html')


@app.route('/checkrole')
def CheckRole():
    role_id = 3
    # user_id = 33771492
   # user_role = RoleAccount.query.get(role_id)
   # print(user_role.role_name)
   # user = user_role.users
   # print(user)
   
    # request_body = request.get_json()
    # user_id = request_body['user_id']
    # myrole = UserAccount.query.get(user_id).role
    # my_role= myrole.role_name
   # myrole_id = UserAccount.query.get(user_id)
   # print(myrole_id.role_id)
    # return f"my role is {my_role}"
    users = UserAccount.query.filter_by(role_id=role_id).first()
    # print(users.firstname)
    return render_template('users.html', userz = users)

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
            registered_user = UserAccount(id,firstname,lastname,username,encrpted_pass.decode(),phone,encrpted_pin.decode())

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
        current_user = UserAccount.query.filter_by(username=username).first()

        # check the existence of the person in the database
        # if current_user is not None:(opposite statement)
        if current_user is None:
             return render_template("login_error.html")
        else:
            # get the password and encrypt it and check the match with the one encrypted in the database(will be success or error)
             result = bcrypt.checkpw(password.encode(), current_user.password.encode())
             if result:
                 # check if he/she is the admin 
                 if current_user.role_id == 1:
                    return render_template('admin_home.html')
                 else:
                    return render_template('user_home.html', user = current_user)
             else:
                 return render_template("login_error.html")
    return render_template('login.html')


@app.route('/home')
# @Login_required
def Home():
    # current_user = UserAccount.query.filter_by(username=username).first()
    return render_template("user_home.html")

@app.route('/admin')
def Admin():
    return render_template("admin_home.html")

@app.route('/admin/account')
def AdminAccount():
    return render_template("admin.html")

@app.route('/home/account')
def Account():
    return render_template("account.html")


@app.route('/logout')
def Logout():
    return render_template("logout.html")

@app.route('/userDetails')
def UserEditing():
    user_id = 33771492
    current_user = UserAccount.query.get(user_id)
    return render_template("user_details.html", user = current_user)

@app.route('/usersaving', methods = ['POST','GET'])
# def UserSaving():
#     if request.method == "POST":
#         # user_id = 33771490
#         user_id = request.form.get('id_no')
#         name = request.form.get('name2')
#         current_user = UserAccount.query.get(user_id)

#         current_user.firstname = name
#         db.session.add(current_user)
#         db.session.commit()
                            
#         one_user = UserAccount.query.get(user_id)
#     return render_template("user_details.html", user = one_user)

def PhotoUpload():
    if request.method == "POST":
        user_id = 33771492
        pic = request.files['pic']
        if not pic:
            return "no pic uploaded",400

        # pic.save(secure_filename(pic.filename))
        # filename1 = pic.read()
        # nimetype = pic.mimetype
        # filename1 = secure_filename(pic.filename)
        user = UserAccount.query.get(user_id)
        # img = UserAccount(profile_pic = filename)
        filename = secure_filename(pic.filename)
        pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        user.profile_pic = filename
        db.session.add(user)
        db.session.commit()

        one_user = UserAccount.query.get(user_id)
        # user.profile_pic = filename
    return render_template("user_details.html", user= one_user)


@app.route('/account/check_balance', methods=['POST','GET'])
def CheckBalance():
    if request.method == "POST":
        id = request.form.get('id_no')
        pin = request.form.get('pin_no')
        current_user = UserAccount.query.filter_by(id=id).first()

        if current_user is not None:
            if current_user.role_id != 1:
                result = bcrypt.checkpw(pin.encode(), current_user.pin.encode())
                if result:
                    if current_user.role_id == 3:
                        time = datetime.datetime.now().strftime("%d/%m/%Y at %I:%M %p")
                        return render_template('user_balance.html', user = current_user, the_time = time)
                    elif current_user.role_id == 2:
                        time = datetime.datetime.now().strftime("%d/%m/%Y at %I:%M %p")
                        return render_template('user_balance.html', agent = current_user, the_time = time)
                else:
                    pin_mismatch = "Sorry! You have entered wrong PIN. Try again."
                    return render_template('user_balance.html', errored_pin_msg = pin_mismatch)
            else:
                try_check = "The ID does not match the registered ID! Please confirm your ID number and try again."
                return render_template('user_balance.html', check_msg = try_check)
        else:
             not_found_msg = "Invalid ID! Please confirm your ID number and try again."
             return render_template('user_balance.html', not_found = not_found_msg )
    return render_template("account.html")


@app.route('/admin/check_balance', methods=['POST','GET'])
def CheckBalanceAdmin():
    if request.method == "POST":
        id = request.form.get('id_no')
        pin = request.form.get('pin_no')
        current_admin = UserAccount.query.filter_by(id=id).first()

        if current_admin is not None:
            if current_admin.role_id == 1:
                result = bcrypt.checkpw(pin.encode(), current_admin.pin.encode())
                if result:
                    time = datetime.datetime.now().strftime("%d/%m/%Y at %I:%M %p")
                    return render_template('admin_balance.html', admin = current_admin, the_time = time)
                else:
                    pin_mismatch = "Sorry! You have entered wrong PIN. Try again."
                    return render_template('admin_balance.html', errored_pin_msg = pin_mismatch)
            else:
                try_check = "The ID does not match the registered ID! Please confirm your ID number and try again."
                return render_template('admin_balance.html', check_msg = try_check)
        else:
             not_found_msg = "Invalid ID! Please confirm your ID number and try again."
             return render_template('admin_balance.html', not_found = not_found_msg)
    return render_template("admin.html")


@app.route('/account/deposit', methods= ['GET','POST'])
def Deposit():
    # a varible to get agent
    if request.method == 'POST':
        agent_id = request.form.get('agent_id') 

        # variable to store the agent by (get) to obtain one
        # to get more than one agent use (filter_by()) 
        agent = UserAccount.query.get(agent_id)

        # variable to define the agent_pin and the amount to deposit
        pin = request.form.get('pin_no')
        amount = int(request.form.get('amount'))

        if agent is not None:
            if agent.role_id == 2:
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
                            # one_agent = UserAccount.query.get(agent_id)
                            time = datetime.datetime.now().strftime("%d/%m/%Y at %I:%M %p")
                            new_balance = one_user.account_balance
                            theID = user.id
                            theAgent = agent.id
                            return render_template('user_balance.html', the_user=one_user, time=time, new_balance=new_balance, theID=theID, theAgent=theAgent)
                        else:
                            no_user = "Invalid user ID! Please confirm the user ID number and try again."
                            return render_template('user_balance.html', no_user_found = no_user)
                    else:
                        # the agent account has no enough money to deposit
                        no_float_msg= 'Sorry! You have no enough funds to deposit Ksh {}.'.format(amount)
                        return render_template("user_balance.html", no_float = no_float_msg)
                else:
                    agent_pin_error = "Sorry! You have entered wrong PIN. Try again."
                    return render_template('user_balance.html', agent_pinerror = agent_pin_error)
            else:
                no_agent = "Agent not found! Confirm your ID number and try again."
                return render_template('user_balance.html', no_agent_found = no_agent)
        else:
            no_agent = "Agent not found! Confirm your ID number and try again."
            return render_template('user_balance.html', no_agent_found = no_agent)
    return render_template('account.html')
    

@app.route('/admin/deposit', methods= ['GET','POST'])
def DepositAdmin():
    if request.method == 'POST':
        admin_id = request.form.get('admin_id')  
        admin = UserAccount.query.get(admin_id)

        # variable to define the admin_pin and the amount to deposit
        pin = request.form.get('pin_no')
        amount = int(request.form.get('amount'))

        if admin is not None:
            if admin.role_id == 1:
                result = bcrypt.checkpw(pin.encode(), admin.pin.encode())
                if result:
                    # to check if the float is enough to deposit the amount
                    if admin.float_balance >= amount:

                        # go find a user
                        user_id = request.form.get('user_id')
                        user = UserAccount.query.get(user_id)
                        if user:
                            # deposit the amount to their account and update admin float_balance
                            user.account_balance += amount
                            db.session.add(user)
                            db.session.commit()

                            admin.float_balance -= amount
                            db.session.add(admin)
                            db.session.commit()
                            
                            one_user = UserAccount.query.get(user_id)
                            new_balance = one_user.account_balance
                            time = datetime.datetime.now().strftime("%d/%m/%Y at %I:%M %p")
                            theID = user.id
                            theAdmin = admin.id
                            return render_template('admin_balance.html', the_user=one_user, time=time, new_balance=new_balance, theID=theID, theAdmin=theAdmin)
                        else:
                            no_user = "Invalid user ID! Please confirm the user ID number and try again."
                            return render_template('admin_balance.html', no_user_found = no_user)
                    else:
                        no_float_msg= 'Sorry! You have no enough funds to deposit Ksh {}.'.format(amount)
                        return render_template("admin_balance.html", no_float = no_float_msg)
                else:
                    admin_pin_error = "Sorry! You have entered wrong PIN. Try again."
                    return render_template('admin_balance.html', admin_pinerror = admin_pin_error)
            else:
                no_admin = "Admin not found! Confirm your ID number and try again."
                return render_template('admin_balance.html', no_admin_found = no_admin)
        else:
            no_admin = "Admin not found! Confirm your ID number and try again."
            return render_template('admin_balance.html', no_admin_found = no_admin)
    return render_template('admin.html')


@app.route('/account/withdraw', methods= ['GET','POST'])
def Withdraw():
    if request.method == 'POST':
        agent_id = request.form.get('agent_id')
        user_id = request.form.get('user_id')
        pin = request.form.get('pin_no')
        amount = int(request.form.get('amount'))
        agent = UserAccount.query.get(agent_id)
        user = UserAccount.query.get(user_id)

        if agent is not None:
            if agent.role_id == 2:
                if user is not None:
                    result = bcrypt.checkpw(pin.encode(), user.pin.encode()) 
                    if result:
                        if user.account_balance >= amount:
                            user.account_balance = user.account_balance - (amount + (0.03*amount))
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
                            return render_template('user_balance.html', that_user=one_user, time=time, new_balance=new_balance, theID=theID, theAgent=theAgent)
                        else:
                            withdraw_error_message = 'Sorry! You have insufficient balance to withdraw such amount.'
                            return render_template('user_balance.html', withdraw_error_msg = withdraw_error_message)  
                    else:
                        pin_occured_err = "Sorry! You have entered wrong PIN. Try again"
                        return render_template('user_balance.html', pin_err = pin_occured_err) 
                else:
                    userID_error = "Invalid ID! Please confirm your ID number and try again."
                    return render_template('user_balance.html', user_id_error = userID_error)
            else:
                agentID_error = "Agent not found! Confirm the Agent ID and try again."
                return render_template('user_balance.html', agentID_err = agentID_error)
        else:
            agentID_error = "Agent not found! Confirm the Agent ID and try again."
            return render_template('user_balance.html', agentID_err = agentID_error)
    return render_template('account.html')


@app.route('/admin/withdraw', methods= ['GET','POST'])
def WithdrawAdmin():

    agent_id = request.form.get('agent_id')
    user_id = request.form.get('user_id')
    pin = request.form.get('pin_no')
    amount = int(request.form.get('amount'))
    admin = UserAccount.query.get(agent_id)
    user = UserAccount.query.get(user_id)

    if request.method == 'POST':
        if admin is not None:
            if admin.role_id == 1:
                if user is not None:
                    result = bcrypt.checkpw(pin.encode(), user.pin.encode()) 
                    if result:
                        if user.account_balance >= amount:
                            user.account_balance = user.account_balance - (amount + (0.03*amount))
                            db.session.add(user)
                            db.session.commit()

                            admin.float_balance += amount
                            db.session.add(admin)
                            db.session.commit()

                            one_user = UserAccount.query.get(user_id)
                            time = datetime.datetime.now().strftime("%d/%m/%Y at %I:%M %p")
                            new_balance = one_user.account_balance
                            theID = user.id
                            theAdmin = admin.id
                            return render_template('admin_balance.html', that_user=one_user, time=time, new_balance=new_balance, theID=theID, theAdmin=theAdmin)
                        else:
                            withdraw_error_message = 'Sorry! You have insufficient balance to withdraw such amount'
                            return render_template('admin_balance.html', withdraw_error_msg = withdraw_error_message)  
                    else:
                        pin_occured_err = "Sorry! You have entered wrong PIN. Try again"
                        return render_template('admin_balance.html', pin_err = pin_occured_err) 
                else:
                    userID_error = "Invalid ID! Please confirm your ID number and try again."
                    return render_template('admin_balance.html', user_id_error = userID_error)
            else:
                adminID_error = "Admin not found! Confirm the Admin ID and try again."
                return render_template('admin_balance.html', adminID_err = adminID_error)
        else:
            adminID_error = "Admin not found! Confirm the Admin ID and try again."
            return render_template('admin_balance.html', adminID_err = adminID_error)
    return render_template('admin.html')

if __name__ == "__main__":
    app.run()