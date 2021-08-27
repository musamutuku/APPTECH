from flask import Flask, jsonify, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask.templating import render_template
import bcrypt

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from sqlalchemy.orm import backref


app = Flask(__name__)

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
    age = db.Column(db.Integer)
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))
    account_balance = db.Column(db.Integer, default=0)
    float_balance = db.Column(db.Integer)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), default=3)

    def __init__(self, id, firstname, lastname, age, username, password):
        self.id = id
        self.firstname = firstname
        self.lastname = lastname
        self.age = age
        self.username = username
        self.password = password
        #self.account_balance = account_balance
        #self.float_balance = float_balance
        #self.role_id = role_id

class RoleAccount(db.Model):  
    
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50))
    users = db.relationship('UserAccount', backref='role', lazy=True)
    

@app.route('/')
def index():

  return render_template('index.html')


@app.route('/checkrole', methods= ["POST"])
def CheckRole():
   # role_id = 3
   # user_role = RoleAccount.query.get(role_id)
   # print(user_role.role_name)
   # user = user_role.users
   # print(user)
   
    request_body = request.get_json()
    user_id = request_body['user_id']
    myrole = UserAccount.query.get(user_id).role
    my_role= myrole.role_name
   # myrole_id = UserAccount.query.get(user_id)
   # print(myrole_id.role_id)
    return f"my role is {my_role}"

@app.route('/register', methods = ["POST","GET"])
def Register():

    # getting form details from registration form
    if request.method == "POST":
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        id = request.form.get('id_no')
        age = request.form.get('age')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirm')

        # get/check the entered user_id no and username in the users' table(database) (if any)
        user_ID = UserAccount.query.filter_by(id=id).first()
        current_user = UserAccount.query.filter_by(username=username).first()

        # check if the user_id and username are already used
        if user_ID is None:
            if current_user is not None:
                return jsonify({"msg":"the username is already taken. Use another username"}),409
        else:
            return jsonify({"msg":"the ID is already used"}),409
        
        
        # encrypting the password using hash function
        if confirm == password:
            encrpted_pass =  bcrypt.hashpw(password.encode(), bcrypt.gensalt(14))
            registered_user = UserAccount(id,firstname,lastname,age,username,encrpted_pass.decode())
        else:
            return jsonify({'msg':"password does not match"}),412

        # add the details in the database
        db.session.add(registered_user)
        db.session.commit()
        return jsonify({'msg':"registered successfully"})
    return render_template('register.html')
    

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
                    correct = "You have been logged in successfully"
                    return render_template('user_home.html', success_message = correct, user = current_user)
             else:
                 return render_template("login_error.html")
    return render_template('login.html')

@app.route('/logout', methods= ['POST'])
def Logout():
    return "logged out successfully"


@app.route('/deposit', methods= ['POST'])
def Deposit():
    request_body = request.get_json()

    # variable to get an agent
    agent_id = request_body['agentId']

    # variable to store the agent by (get) to obtain one
    # to get more than one agent use (filter_by()) 
    agent = UserAccount.query.get(agent_id)

    # varible to define the amount to deposit
    amount = request_body['amount']

    if agent is not None:

        # to check if the float is enough to deposit the amount
        if agent.float_balance >= amount:

            # go find a user
            user_id = request_body['userID']
            user = UserAccount.query.get(user_id)

            # deposit the amount to their account
            # return the user object as a json object, return the agent account with the updated float balance
            user.account_balance += amount
            db.session.add(user)
            db.session.commit()

            agent.float_balance -= amount
            db.session.add(agent)
            db.session.commit()
            
            one_user = UserAccount.query.get(user_id)
            one_agent = UserAccount.query.get(agent_id)
            user_data = {
                "account_balance": one_user.account_balance,
                "firstname": one_user.firstname
            }
            agent_data = {
                "username": one_agent.username,
                "float_balance": one_agent.float_balance
            }
            return jsonify(user_data, agent_data)
        else:
            # the agent account has no enough money to deposit
            # user goes away
            error_message = 'no enough funds to deposit {}'.format(amount)
            return error_message
    else:
        return {"error": "agent not found, confirm your id"}

# agent can check balance for a user
@app.route('/checkbalance', methods= ['GET'])
@jwt_required()
def CheckBalance():
    current_user = get_jwt_identity()
    request_body = request.get_json()
    user_id = request_body['userID']

    one_user = UserAccount.query.get(user_id)
    if current_user == one_user.username:
        if one_user is not None:
            user_balance = {
                "account_balance": one_user.account_balance,
                "firstname": one_user.firstname,
                "lastname" : one_user.lastname
            }
            return jsonify(user_balance)
        else:
            return {"error": "user not found, confirm your id"}
    else:
        return "your id does not match to the registered id"
    

@app.route('/withdraw', methods= ['GET'])
def WithdrawCash():
    request_body = request.get_json()
    user_id = request_body['userID']
    user = UserAccount.query.get(user_id)
    amount = request_body['amount']
    if user is not None:
        if user.account_balance >= amount:
            user.account_balance -= amount
            db.session.add(user)
            db.session.commit()
            return 'Your have successfully withdrawn {0}.Your new balance is {1}'.format(amount,user.account_balance)
        else:
            error_message = 'You have insufficient balance to withdraw such amount'
            return error_message
        
    else:
        return {"error": "user not found, confirm your id"}


if __name__ == "__main__":
    app.run()