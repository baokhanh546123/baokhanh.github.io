from flask import Flask ,session, redirect , render_template , request , url_for , flash 
from flask_sqlalchemy import SQLAlchemy 
from flask_login import LoginManager , login_user ,logout_user , login_required , current_user , UserMixin
from flask_mail import Mail 
from passlib.hash import pbkdf2_sha256 
from werkzeug.security import check_password_hash, generate_password_hash
import secrets , string 
web = Flask(__name__)
web.config.from_object('config2.Config2')
web.secret_key = "234567"

login_manager = LoginManager()
login_manager.init_app(web)
login_manager.login_view = 'dangnhap'
db = SQLAlchemy(web)

class login(db.Model,UserMixin):
    __tablename__ = 'login'
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(45) , nullable = False)
    last_name = db.Column(db.String(45) , nullable = False)
    username = db.Column(db.String(50) , nullable = False)
    email = db.Column(db.String(50) , nullable = False , unique = True)
    password_user = db.Column(db.String(50),nullable = False , unique = True)
    password_hash = db.Column(db.String(10000) , nullable = False ,unique = True)
    secret_pass = db.Column(db.String(10),nullable = False , unique = True)
    def __repr__(self):
        return f"User {self.username}"
    #Overridding
    def get_id(self):
        return str(self.ID)

def get_user_by_username(username):
    user = db.session.query(login).filter_by(username=username).first()
    return user


def validate_password(password):
    # Check password length
    if len(password) < 10:
        return "Mật khẩu quá ngắn. Độ dài phải từ 10 ký tự trở lên."
    
    # Check for at least one special character
    special_characters = ["@", "#", "$", "%", "!", "*", "&"]
    if not any(char in special_characters for char in password):
        return "Mật khẩu cần có ít nhất một ký tự đặc biệt."

    # Check for lowercase, uppercase and digits
    if not any(char.islower() for char in password):
        return "Mật khẩu cần chứa ít nhất một chữ cái thường."
    if not any(char.isupper() for char in password):
        return "Mật khẩu cần chứa ít nhất một chữ cái hoa."
    if not any(char.isdigit() for char in password):
        return "Mật khẩu cần chứa ít nhất một chữ số."

    return None  # Password is valid

@login_manager.user_loader
def load_user(user_id):
    return login.query.get(int(user_id))

# Ensure the database tables are created
with web.app_context():
    db.create_all()

@web.route('/')
@login_required
def home():
    return render_template("home1.html" , user = current_user) 

def home1():
    return render_template('home.html', current_page=1, total_pages=2)


 
@web.route('/dangky', methods=['GET', 'POST'])
def dangky():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        email = request.form['email']
        password_user = request.form['password']
        
        
        # Password validation
        length = 10
        special_characters = ["@", "#", "$", "%", "!", "*", "&"]

        # Check if password length is less than 10 characters
        if len(password_user) < length:
            flash("Mật khẩu quá ngắn", "danger")
            return render_template("dangky.html")

        # Check if password contains at least one special character
        if not any(char in special_characters for char in password_user):
            flash("Mật khẩu cần có một ký tự đặc biệt", "danger")
            return render_template("dangky.html")

        # Check if the username already exists
        existing_user = login.query.filter_by(username=username).first()
        existing_email = login.query.filter_by(email=email).first()

        if existing_user or existing_email:
            flash("Tài khoản này đã tồn tại", "error")
            return render_template('dangky.html')
        secret_pass = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
        password_hash = pbkdf2_sha256.hash(password_user)
        # Create new user and save to the database
        new_user = login(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            password_user = password_user,
            password_hash=password_hash,
            secret_pass = secret_pass
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Đăng ký thành công! Vui lòng đăng nhập", "success")
        return redirect(url_for('dangnhap'))

    return render_template('dangky.html')

@web.route('/dangnhap', methods=['GET', 'POST'])
def dangnhap():
    if request.method == 'POST':
        username = request.form['username']
        password_user = request.form['password']

        # Retrieve user from the database
        user = login.query.filter_by(username=username).first()

        if user and pbkdf2_sha256.verify(password_user, user.password_hash):  # Compare with password_hash
            login_user(user)
            return redirect(url_for('home'))  # Redirect to the homepage or dashboard
        else:
            flash("Tài khoản hoặc mật khẩu không chính xác", "danger")
    
    return render_template('dangnhap.html')

@web.route('/quenmatkhau', methods=['GET', 'POST'])
def quenmatkhau():
    if request.method == 'POST':
        username = request.form['username']
        secret_pass = request.form['secret_pass']

        # Tìm người dùng trong cơ sở dữ liệu theo tên đăng nhập
        user = login.query.filter_by(username=username).first()
        
        if not user:
            flash("Tài khoản không tồn tại!", "danger")
            return redirect(url_for('quenmatkhau'))

        # Kiểm tra mã bảo mật (secret_pass) có đúng không
        if secret_pass != user.secret_pass:
            flash("Mã bảo mật không đúng!", "danger")
            return redirect(url_for('quenmatkhau'))  # Giữ lại ở trang quên mật khẩu

        # Nếu mã bảo mật đúng, chuyển đến trang thay đổi mật khẩu
        return redirect(url_for('doimatkhau'))

    return render_template('quenmatkhau.html')

@web.route('/doimatkhau', methods=['GET', 'POST'])
@login_required
def doimatkhau():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if the current password matches the user's password
        if not check_password_hash(current_user.password_hash, current_password):
            flash("Mật khẩu cũ không chính xác!", "danger")
            return render_template('doimatkhau.html', user=current_user)

        # Check if new password and confirm password match
        if new_password != confirm_password:
            flash("Mật khẩu mới và xác nhận mật khẩu không trùng khớp!", "danger")
            return render_template('doimatkhau.html', user=current_user)

        # Validate the new password
        password_error = validate_password(new_password)
        if password_error:
            flash(password_error, "danger")
            return render_template('doimatkhau.html', user=current_user)

        # Hash the new password and update it
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        flash("Mật khẩu đã được thay đổi thành công!", "success")
        return redirect(url_for('home'))

    return render_template('doimatkhau.html', user=current_user)


@web.route('/dangxuat')
@login_required 
def dangxuat():
    logout_user()
    return redirect(url_for("dangnhap"))


@web.route('/thongtin', methods=['GET', 'POST'])
@login_required  # Ensure only logged-in users can update their info
def thongtin():
    if request.method == 'POST':
        # Get the data from the form
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        password_user = request.form.get('password')  # New password

        # Update the current user data
        current_user.first_name = first_name
        current_user.last_name = last_name

        # Optionally, update the username if the user changed it
        if username != current_user.username:
            current_user.username = username    

        # Check if the user wants to change the password
        if password_user:
            # Check if the new password is the same as the current one
            if pbkdf2_sha256.verify(password_user, current_user.password_hash):
                flash("Mật khẩu mới không được giống với mật khẩu cũ!", "danger")
                return render_template('thongtin.html', user=current_user)

            # Password validation
            length = 10
            special_characters = ["@", "#", "$", "%", "!", "*", "&"]

            # Check if new password length is less than 10 characters
            if len(password_user) < length:
                flash("Mật khẩu mới quá ngắn. Độ dài phải từ 10 ký tự trở lên.", "danger")
                return render_template('thongtin.html', user=current_user)

            # Check if new password contains at least one special character
            if not any(char in special_characters for char in password_user):
                flash("Mật khẩu mới cần có ít nhất một ký tự đặc biệt.", "danger")
                return render_template('thongtin.html', user=current_user)

            # Check if password_user is None or empty
            if not password_user:
                flash("Mật khẩu không được để trống!", "danger")
                return render_template('thongtin.html', user=current_user)

            # Hash the new password and update it
            current_user.password_hash = pbkdf2_sha256.hash(password_user)

        # Commit the changes to the database
        db.session.commit()

        # Flash a success message
        flash("Thông tin cá nhân đã được cập nhật thành công!", "success")

        # Redirect to the home page
        return redirect(url_for('home'))

    return render_template('thongtin.html', user=current_user)



#
@web.route('/xoa_tai_khoan', methods=['POST', 'GET'])
@login_required
def xoa_tai_khoan():
    if request.method == 'POST':
        # Xóa tài khoản của người dùng hiện tại
        db.session.delete(current_user)
        db.session.commit()

        # Đăng xuất người dùng
        logout_user()

        # Hiển thị thông báo
        flash("Tài khoản đã được xóa thành công!", "success")

        # Chuyển hướng về trang đăng nhập
        return redirect(url_for("dangnhap"))

    return render_template("thongtin.html")

@web.route('/page2')
def page2():
   return render_template('page2.html',current_page=2,total_pages=2)
@web.route('/page3')
def page3():
   return render_template('page3.html',current_page=3,total_pages=3)
@web.route('/page4')
def page4():
    return render_template('page4.html',current_page=4,total_pages=4)

    
if __name__ == '__main__':
    web.run(debug = True , host = '0.0.0.0' , port = 5000)