from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import bcrypt

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from sqlalchemy.orm import backref


app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret" 
jwt = JWTManager(app)

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
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __init__(self, firstname, lastname, age, username, password,role_id):
        self.firstname = firstname
        self.lastname = lastname
        self.age = age
        self.username = username
        self.password = password
        #self.account_balance = account_balance
        #self.float_balance = float_balance
        self.role_id = role_id

class RoleAccount(db.Model):  
    
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50))
    users = db.relationship('UserAccount', backref='role', lazy=True)
    

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

@app.route('/register', methods = ["POST"])
def Register():
    request_body = request.get_json()
    username = request_body.get('username')

    current_user = UserAccount.query.filter_by(username=username).first()
    if current_user is not None:
        return jsonify({"msg":"the username is already taken. Use another username"}),409

    firstname = request_body['firstname']
    lastname = request_body['lastname']
    age = request_body['age']
    username = request_body['username']
    password = request_body['password']
    role_id = request_body['role_id']
    
    encrpted_pass =  bcrypt.hashpw(password.encode(), bcrypt.gensalt(14))
    registered_user = UserAccount(firstname,lastname,age,username,encrpted_pass.decode(),role_id)

    db.session.add(registered_user)
    db.session.commit()
    return jsonify({'msg':"registered successfully"})
    

@app.route('/login', methods=['POST'])
def Login():

    request_body = request.get_json()
    username = request_body['username']
    password = request_body['password']
    #if request.method=="POST":

       #username=request.form.get('username')
       #password=request.form.get('password')

    current_user = UserAccount.query.filter_by(username=username).first()

    if current_user is not None:
        result = bcrypt.checkpw(password.encode(), current_user.password.encode())
        if current_user and result:
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token)
        else:
            return jsonify({"msg": "incorrect username or password"}), 401
    else:
        return "user does not exist"
    

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
    app.run(debug=True)