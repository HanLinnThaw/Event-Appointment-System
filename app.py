from flask import Flask, render_template, redirect, url_for, request, flash ,session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.secret_key ="Event Management"


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'gatherhubgp8@gmail.com'  
app.config['MAIL_PASSWORD'] = 'tulg hqyo ogdm lhwm'  
mail = Mail(app)


def role_required(role):
    """Decorator to restrict access based on user role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_type' not in session or session['user_type'] != role:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'jfif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

UPLOAD_FOLDER = 'static/photo'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
           
upload_folder = os.path.join('static','upload_photo')
app.config['upload_photo']= upload_folder

DEFAULT_IMAGE_PATH = '/static/photo/profile.jpeg'  

def get_db_connection():
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/userdashboard')
@app.route('/')
def dashboard():
    sponsorlist2 = []
    testid= 1
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dashboard where id=?",(testid,))
    setting = cursor.fetchone()
    cursor.execute("SELECT * from aboutussetting where id=?", (testid,))
    setting1 = cursor.fetchone()
    cursor.execute("SELECT * from event")
    eventlist = cursor.fetchall()
    cursor.execute("SELECT * FROM sponsor")
    sponsorlist1 = cursor.fetchall()
    for sponsor in sponsorlist1:
        conn = sqlite3.connect('event.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        sponsorid = sponsor['sponsorid']
        cursor.execute("select name from sponsor where sponsorid=?", (sponsorid,))
        sponsorname = cursor.fetchone()
        sponsorlist2.append(sponsorname)
    events_with_sponsors = []
    print(sponsorlist2)
    for event, sponsor in zip(eventlist, sponsorlist2):
        events_with_sponsors.append({
            'event': event,
            'sponsor': sponsor
        })
    return render_template('userdashboard.html', setting = setting, setting1 = setting1, events_with_sponsors=events_with_sponsors, sponsorlist1 = sponsorlist1)


# Route to display the login page
@app.route('/Login', methods=['GET', 'POST'])
def Login():
    if request.method == 'POST':
        # Get form data
        email = request.form['email']
        password = request.form['password']
        
        # Connect to the database
        conn = sqlite3.connect('event.db')
        cursor = conn.cursor()
        
        try:
            # Query to get the hashed password, user type, and image for the provided email
            cursor.execute('SELECT userid, password, type, image FROM users WHERE email=?', (email,))
            result = cursor.fetchone()
            
            if result:
                user_id, hashed_password, user_type, image = result
                
                # Verify the password using check_password_hash
                if check_password_hash(hashed_password, password):
                    # Password is correct; store user info in session
                    session['user_id'] = user_id
                    session['email'] = email
                    session['user_type'] = user_type
                    session['image'] = image if image else '/static/images/default-profile.png'  # Default image
                    
                    # Flash login success message
                    flash('Login successful!', 'success')
                    
                    # Redirect based on user type
                    if user_type == 'admin':
                        return redirect(url_for('admin_page'))  
                    else:
                        return redirect(url_for('dashboard'))  
                else:
                    # Password is incorrect
                    flash('Invalid email or password.', 'danger')
            else:
                # Email not found
                flash('Invalid email or password.', 'danger')
                
        finally:
            # Ensure the connection is closed
            conn.close()
    
    # Render the login form
    return render_template('Login.html')


# Function to validate password strength
def is_strong_password(password):
    if (len(password) >= 8 and 
        re.search(r'[A-Z]', password) and  # At least one uppercase letter
        re.search(r'[a-z]', password) and  # At least one lowercase letter
        re.search(r'[0-9]', password) and  # At least one digit
        re.search(r'[!@#$%^&*]', password)):  # At least one special character
        return True
    return False

# Function to validate email format
def is_valid_email(email):
    # Regex for standard email format
    email_pattern = r'^[\w\.-]+@[a-zA-Z\d\.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email) is not None

# Route to display the sign-up page

# Route to display the sign-up page
@app.route('/SignUp', methods=['GET', 'POST'])
def SignUp():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = 'user'  # Set the type as 'user'
        
        # Use the default image path
        image = DEFAULT_IMAGE_PATH
        
        # Validate email format
        if not is_valid_email(email):
            flash("Invalid email format. Please enter a valid email address.", "danger")
            return render_template('SignUp.html')
        
        # Check if the password is strong
        if not is_strong_password(password):
            flash("Password must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a digit, and a special character.", "danger")
            return redirect(url_for('SignUp'))
        
        # Connect to the database
        conn = sqlite3.connect('event.db')
        cursor = conn.cursor()
        
        # Check if the email already exists
        cursor.execute('SELECT email FROM users WHERE email = ?', (email,))
        existing_email = cursor.fetchone()
        
        if existing_email:
            flash("The email address is already in use. Please use a different email.", "danger")
            conn.close()
            return render_template('SignUp.html')
        
        # Hash the password
        hashed_password = generate_password_hash(password)
        
        # Insert the new user into the database
        cursor.execute('INSERT INTO users (username, email, password, type, image) VALUES (?, ?, ?, ?, ?)', 
                       (username, email, hashed_password, user_type, image))
        conn.commit()
        
        # Close the connection
        conn.close()
        
        # Redirect to the login page after successful sign-up
        flash("Sign-up successful! Please log in.", "success")
        return redirect(url_for('Login'))
    
    # Render the sign-up form
    return render_template('SignUp.html')


@app.route('/navbar')
def navbar():
    return render_template('usernav.html')


@app.route('/ContactUs', methods=['GET', 'POST'])
def ContactUs():
    testid= 1
    conn1 = sqlite3.connect('event.db')
    conn1.row_factory = sqlite3.Row
    cursor1 = conn1.cursor()
    cursor1.execute("SELECT * FROM contactussetting where id=?",(testid,))
    setting = cursor1.fetchone()
    if request.method == 'POST':
        # Retrieve data from the form
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        address = request.form.get('address')
        message = request.form.get('message')

        # Connect to the SQLite database
        conn = sqlite3.connect('event.db')
        cursor = conn.cursor()

        # Insert the form data into the contact table
        cursor.execute('''
            INSERT INTO contact (name, phone, email, address, message)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, phone, email, address, message))

        # Commit the changes and close the connection
        conn.commit()
        conn.close()
        
        # Flash a success message with a specific category
        flash("Thank you for contacting us! We will get back to you shortly.", "contact_success")

        # Redirect to the same page after submission
        return redirect(url_for('ContactUs', setting = setting))
    
    # Render the Contact Us page
    return render_template('ContactUs.html', setting = setting)

@app.route('/contactlist')
def contactlist():
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM contact")
    messagelist = cursor.fetchall()
    cursor.execute("select count(contactid) from contact")
    count = cursor.fetchone()
    message_count = count[0]
    setting = cursor.fetchone()
    return render_template('ContactUslist.html', messagelist = messagelist, message_count = message_count)

@app.route('/delete_contact/<int:contactid>', methods=['GET'])
def delete_contact(contactid):
    conn = sqlite3.connect('event.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM contact WHERE contactid = ?", (contactid,))
    conn.commit()
    conn.close()
    flash('Message is deleted successfully!', 'event_success')
    return redirect(url_for('contactlist'))

@app.route('/aboutus')
def aboutus():
    testid= 1
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM aboutussetting where id=?",(testid,))
    setting = cursor.fetchone()
    return render_template('AboutUs.html', setting = setting)

@app.route('/event')
def event():
    # Connect to the database
    connection = sqlite3.connect("event.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    
    cursor.execute("select * from category")
    category = cursor.fetchall()
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row  # Fetch rows as dictionaries
    
    # Fetch the events with their category names
    query = '''
    SELECT e.*, c.name AS category_name
    FROM event e
    LEFT JOIN category c ON e.categoryid = c.Categoryid
    '''
    events = conn.execute(query).fetchall()
    Categoryid = request.args.get('Categoryid')
    print(Categoryid)
    if Categoryid:
            cursor.execute("select * from event where categoryid=?",(Categoryid,))
            events = cursor.fetchall()
            return render_template("EventPage.html", events = events, category = category)
    
    # Close the database connection
    conn.close()
    
    # Pass events to the template
    return render_template('EventPage.html', events=events, category = category)

@app.route('/eventdetail/<int:event_id>', methods=['GET', 'POST'])
def eventdetail(event_id):
    print(event_id)
    # Connect to the database
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row  # Fetch rows as dictionaries

    # Fetch the event details along with the category name and sponsor details
    query = '''
    SELECT e.*, c.name AS category_name, s.name AS sponsor_name, s.image AS sponsor_image, s.Description AS sponsor_description, f.foodname AS foodname
    FROM event e
    LEFT JOIN category c ON e.categoryid = c.categoryid
    LEFT JOIN sponsor s ON e.sponsorid = s.sponsorid
    LEFT JOIN foodtable f ON e.food = f.foodid
    WHERE e.eventid = ?
    '''
    event = conn.execute(query, (event_id,)).fetchone()
    print
    # Close the database connection
    conn.close()

    if request.method == 'POST':
        # Handle the booking form submission
        if 'email' not in session:
            flash('Please log in to make a booking.', 'danger')
            return redirect(url_for('Login'))

        try:
            # Get form data from the request
            booking_data = {
                'userid': session.get('user_id'),  
                'eventid': event_id,  # Use the current event ID
                'name': request.form.get('name'),
                'phone': request.form.get('phone'),
                'email': request.form.get('email'),
                'address': request.form.get('address'),
                'totalperson': request.form.get('Total'),
                'totalcost': request.form.get('cost'),
                'message': request.form.get('message'),
            }
            totalperson = request.form.get('Total')
            print(totalperson)
            # Connect to the database
            conn = sqlite3.connect('event.db')
            cursor = conn.cursor()
            cursor.execute("select totalpersons from event where eventid=?",(event_id,))
            available = cursor.fetchone()
            max_person = available[0]
            max_person = int(max_person)
            totalperson = int(totalperson)
            print(type(max_person))
            print(type(totalperson))
            if totalperson <= max_person:
            # Insert booking data into requestbooking table
                cursor.execute('''
                    INSERT INTO requestbooking (userid, eventid, name, phone, email, address, totalperson, totalcost, message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    booking_data['userid'],
                    booking_data['eventid'],
                    booking_data['name'],
                    booking_data['phone'],
                    booking_data['email'],
                    booking_data['address'],
                    booking_data['totalperson'],
                    booking_data['totalcost'],
                    booking_data['message'],
                ))
                # Commit and close the connection
                conn.commit()
                conn.close()
                # Display a success message to the user
                flash('Booking request submitted successfully!', 'success')

                # Redirect to the same event detail page
                return redirect(url_for('eventdetail', event_id=event_id))
            else:
                flash('Your Booking person is more than available', 'danger')
                return redirect(url_for('eventdetail', event_id=event_id))

        except Exception as e:
            # Log the error and display an error message
            flash(f'Error while submitting booking request: {str(e)}', 'danger')
            return redirect(url_for('eventdetail', event_id=event_id))

    # Pass event details to the template
    return render_template('EventDetailPage.html', event=event)
# Generate a secure token
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')

def send_reset_email(email, token):
    msg = Message('Password Reset Request',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    link = url_for('password_reset', token=token, _external=True)
    msg.html = f'<p>You requested a password reset. Please use the following link to reset your password:</p><a href="{link}">Reset Password</a>'
    mail.send(msg)
    
    
# Route to request a password reset
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user:
            token = generate_reset_token(email)
            send_reset_email(email, token)
            flash('A password reset link has been sent to your email.','success')
            return redirect(url_for('Login'))
        else:
            flash("Email is invalid","danger")
            return redirect(url_for('reset_password_request'))
        
        
    
    return render_template('reset_password_request.html')

@app.route('/password_reset/<token>', methods=['GET', 'POST'])

def password_reset(token):
    try:
        email = URLSafeTimedSerializer(app.config['SECRET_KEY']).loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The reset link is invalid or has expired.')
        return redirect(url_for('Login'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['password1']
        if new_password == confirm_password:
            hashed_password = generate_password_hash(new_password)
        else:
            flash('Enter the same password and recover again!',"danger")
            return redirect(url_for('reset_password_request'))
            
        
        conn = get_db_connection()
        conn.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
        conn.commit()
        conn.close()
        
        flash('Your password has been updated!',"success")
        return redirect(url_for('Login'))
    
    return render_template('ResetPassword.html', token=token)

# Display Forget Password Page
@app.route('/forgetpassword', methods=['GET', 'POST'])
def forgetpassword():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        
        # Connect to the database
        conn = sqlite3.connect('event.db')
        cursor = conn.cursor()

        # Check if user exists with the provided username and email
        cursor.execute("SELECT * FROM users WHERE username = ? AND email = ?", (username, email))
        user = cursor.fetchone()

        if user:
            # Simulate sending a reset link (for demonstration purposes)
            flash(f"A reset link has been generated for {username}. (Simulated, no real email sent)", "info")
            
            # Prepare to reset password directly for the sake of this project
            return redirect(url_for('reset_password', username=username, email=email))
        else:
            flash("Invalid username or email!", "danger")
        
        conn.close()
    
    return render_template('ForgetPassword.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        new_password = request.form['password']
        
        # Connect to the database
        conn = sqlite3.connect('event.db')
        cursor = conn.cursor()

        # Hash the new password
        hashed_password = generate_password_hash(new_password)
        
        # Update the password in the database
        cursor.execute("UPDATE users SET password = ? WHERE username = ? AND email = ?", (hashed_password, username, email))
        conn.commit()  # Ensure the changes are committed
        
        flash("Password updated successfully!", "success")
        return redirect(url_for('Login'))  # Redirect to login page after updating password

    # Get username and email from query parameters
    username = request.args.get('username')
    email = request.args.get('email')
    return render_template('ResetPassword.html', username=username, email=email)


@app.route('/logout')
def logout():
    session.clear()  # Clears all session data
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('Login'))

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()
    connection = sqlite3.connect('event.db')
    cursor = connection.cursor()

    # Search for events by category or name
    cursor.execute("""
        SELECT e.eventid, e.name, e.detail, e.date, e.Time, e.image, c.name AS category_name
        FROM event e
        LEFT JOIN category c ON e.categoryid = c.categoryid
        WHERE e.name LIKE ? OR c.name LIKE ?
    """, (f'%{query}%', f'%{query}%'))
    events = cursor.fetchall()

    # Map results to a list of dictionaries for easier rendering
    event_list = [
        {
            'eventid': event[0],
            'name': event[1],
            'detail': event[2],
            'date': event[3],
            'Time': event[4],
            'image': event[5],
            'category_name': event[6]
        }
        for event in events
    ]
    connection.close()

    return render_template('EventPage.html', events=event_list)

@app.route("/searchadminside", methods=['GET','POST'])
def searchadminside():
    connection = sqlite3.connect("event.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    searchdata = request.form['searchadmin']
    if not searchdata:
        flash('Please enter words to search.', 'danger')
        return redirect(url_for('admin_page')) 
    searchdata = '%' + searchdata + '%'
    cursor.execute('select * from users where username like ?',(searchdata,))
    user = cursor.fetchall()
    if user:
        return redirect(url_for('userlist', searchdata = searchdata))
    cursor.execute('select * from sponsor where name like? ',(searchdata,))
    sponsor = cursor.fetchall()
    if sponsor:
        return redirect(url_for('sponsorlist', searchdata = searchdata))
    cursor.execute('select * from event where name like ?',(searchdata,))
    event = cursor.fetchall()
    if event:
        return redirect(url_for('eventlist', searchdata = searchdata))
    cursor.execute('select * from category where name like ?',(searchdata,))
    categories = cursor.fetchall()
    if categories:
        return redirect(url_for('categories', searchdata = searchdata))
    
    flash('No results found for your search.', 'danger')
    return redirect(url_for('admin_page'))

@app.route('/AdminDashboard')
@role_required('admin')  
def admin_page():
    # Connect to the SQLite database
    conn = sqlite3.connect('event.db')
    cursor = conn.cursor()

    # Query counts for dashboard
    user_count = cursor.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    confirmed_count = cursor.execute('SELECT COUNT(*) FROM bookingtable').fetchone()[0]
    requested_count = cursor.execute('SELECT COUNT(*) FROM requestbooking').fetchone()[0]
    event_count = cursor.execute('SELECT COUNT(*) FROM event').fetchone()[0]
    sponsor_count = cursor.execute('SELECT COUNT(*) FROM sponsor').fetchone()[0]
    message_count = cursor.execute('SELECT COUNT(*) FROM contact').fetchone()[0]

    # Fetch confirmed booking data for the table
    confirmed_bookings = cursor.execute('''
        SELECT bookingid, name, email, address, totalperson, message 
        FROM bookingtable
    ''').fetchall()

    # Close the connection
    conn.close()

    # Render the AdminDashboard.html with data
    return render_template(
        'AdminDashboard.html',
        user_count=user_count,
        confirmed_count=confirmed_count,
        requested_count=requested_count,
        event_count=event_count,
        sponsor_count=sponsor_count,
        message_count=message_count,
        confirmed_bookings=confirmed_bookings
    )

# Dummy route for profileupdate
@app.route('/profileupdate', methods=['GET', 'POST'])
def profileupdate():
    # Check if the user is logged in
    if 'email' in session:
        email = session['email']
        user_id = session['user_id']
        
        # Connect to the database
        conn = sqlite3.connect('event.db')
        cursor = conn.cursor()
        
        conn1 = sqlite3.connect('event.db')
        conn1.row_factory = sqlite3.Row
        cursor1 = conn1.cursor()

        if request.method == 'POST':
            # Retrieve updated values from the form
            new_username = request.form['username']
            new_email = request.form['email']
            photo = request.files.get('photo')
            
            # Handle profile picture upload
            if photo and allowed_file(photo.filename):
                photo_file = secure_filename(photo.filename)
                photo_path = os.path.join(app.config['upload_photo'], photo_file)
                photo.save(photo_path)
                photo_path = '\\' + photo_path
            else:
                # Use existing photo if no new photo is provided
                photo_path = session.get('image', None)

            # Update the user's username, email, and image in the database
            cursor.execute(
                'UPDATE users SET username = ?, email = ?, image = ? WHERE email = ?',
                (new_username, new_email, photo_path, email)
            )
            conn.commit()
            
            # Update session email and close connection
            session['email'] = new_email
            session['image'] = photo_path
            email = new_email
            flash("Profile updated successfully!", "success")

        # Fetch updated user details
        eventnamelist = []
        event_detail = []
        cursor.execute('SELECT username, email, image, password FROM users WHERE email = ?', (email,))
        user_info = cursor.fetchone()
        cursor1.execute('SELECT * FROM requestbooking WHERE userid = ?', (user_id,))
        bookings = cursor1.fetchall()
        for book in bookings:
            eventid = book['eventid']
            print(eventid)
            cursor1.execute("SELECT name FROM event WHERE eventid = ?", (eventid,))
            eventname = cursor1.fetchone()
            eventnamelist.append(eventname)
        for requested, event in zip(bookings, eventnamelist):
            event_detail.append({
                'event': event,
                'requested': requested
            })

        # Fetch confirmed bookings for the user
        confirmed_bookings = []
        cursor1.execute("""
               SELECT b.bookingid, b.userid, u.username, b.email, b.address, b.totalperson, b.message, e.name AS event_name
                FROM bookingtable b
                JOIN users u ON b.userid = u.userid
                JOIN event e ON b.eventid = e.eventid
                WHERE b.userid = ?
                """, (user_id,))
        confirmed_bookings = cursor1.fetchall()
        conn.close()

        if user_info:
            username, email, image, password = user_info
            return render_template(
                'ProfileUpdate.html',
                username=username,
                email=email,
                image=image,
                password=password,
                event_detail=event_detail,
                confirmed_bookings=confirmed_bookings
            )
        else:
            flash('User information not found.', 'danger')
            return redirect(url_for('dashboard'))
    else:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('Login'))



@app.route('/delete-requested-booking/<int:bookingid>', methods=['GET'])
def delete_requested_booking(bookingid):
    try:
        # Connect to the database
        connection = sqlite3.connect('event.db')
        cursor = connection.cursor()

        # Delete the requested booking from the database
        cursor.execute("DELETE FROM requestbooking WHERE bookingid = ?", (bookingid,))
        connection.commit()     

    except sqlite3.Error as e:
        flash(f"An error occurred: {e}", "error")

    finally:
        # Close the connection
        connection.close()

    # Redirect to the page displaying booking history
    return redirect(url_for('profileupdate'))
 


@app.route('/userlist')
@role_required('admin')
def userlist():
    try:
        # Connect to the database
        connection = sqlite3.connect('event.db')
        cursor = connection.cursor()

        # Fetch all users
        cursor.execute("SELECT userid, username, email, type FROM users")
        users = cursor.fetchall()
        searchdata = request.args.get('searchdata')
        if searchdata:
            cursor.execute("select * from users where username like ?",(searchdata,))
            searchdata = cursor.fetchall()
            print(searchdata)
            return render_template('UserList.html', searchdata = searchdata)
        # Render the template with user data
        connection.close()
        return render_template('UserList.html', users=users)
    except Exception as e:
        print(f"Error fetching users: {e}")
        return "An error occurred while fetching users."

# Route to delete a user
@app.route('/deleteuser/<int:userid>', methods=['GET'])
@role_required('admin')
def delete_user(userid):
    try:
        # Connect to the database
        connection = sqlite3.connect('event.db')
        cursor = connection.cursor()

        # Delete the user with the specified userid
        cursor.execute("DELETE FROM users WHERE userid = ?", (userid,))
        connection.commit()
        connection.close()

        # Redirect back to the user list
        return redirect('/userlist')
    except Exception as e:
        print(f"Error deleting user: {e}")
        return "An error occurred while deleting the user."

@app.route('/addadmin', methods=['POST'])
@role_required('admin')
def add_admin():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = 'admin'  # Set the type as 'user'
        
        # Use the default image path
        image = DEFAULT_IMAGE_PATH
        
        # Validate email format
        if not is_valid_email(email):
            flash("Email is not in format","danger")     
            return redirect(url_for('userlist'))      

        
        # Check if the password is strong
        if not is_strong_password(password): 
            flash("Password is not in format","danger")          
            return redirect(url_for('userlist'))
        
        # Hash the password
        hashed_password = generate_password_hash(password)
        
        # Connect to the database
        conn = sqlite3.connect('event.db')
        cursor = conn.cursor()
        
        # Insert the new user into the database
        cursor.execute('INSERT INTO users (username, email, password, type, image) VALUES (?, ?, ?, ?, ?)', 
                       (username, email, hashed_password, user_type, image))
        conn.commit()
        
        # Close the connection
        conn.close()
        
        # Redirect to the login page after successful sign-up
        return redirect(url_for('Login'))
    
    # Render the sign-up form
    return render_template('UserList.html')



@app.route("/categories", methods=["GET", "POST"])
@role_required("admin")
def categories():
    if request.method == "POST":
        category_name = request.form["category"]

        # Check if the category already exists
        conn = get_db_connection()
        existing_category = conn.execute(
            "SELECT * FROM category WHERE name = ?", (category_name,)
        ).fetchone()

        if existing_category:
            # Flash duplicate message
            flash("Category already exists!", "warning")
        else:
            # Add new category to the database
            conn.execute(
                "INSERT INTO category (name) VALUES (?)", (category_name,)
            )
            conn.commit()
            # Flash success message
            flash("Category added successfully!", "success")
        
        conn.close()
        return redirect(url_for("categories"))

    # Fetch categories from the database
    conn = get_db_connection()
    searchdata = request.args.get('searchdata')
    categories = conn.execute("SELECT * FROM category").fetchall()
    if searchdata:
        categories = conn.execute("SELECT * FROM category where name like ?",(searchdata,)).fetchall()
        return render_template("Categories.html", categories = categories)
    return render_template("Categories.html", categories=categories)

@app.route('/delete_category/<int:category_id>', methods=['GET', 'POST'])
@role_required('admin')
def delete_category(category_id):
    # Connect to the database
    conn = get_db_connection()
    
    # Delete the category from the database
    conn.execute('DELETE FROM category WHERE Categoryid = ?', (category_id,))
    
    # Commit changes and close the connection
    conn.commit()
    conn.close()
    
    # Redirect back to the category list page
    flash("Category is deleted Successfully","success")
    return redirect(url_for('categories'))

@app.route('/updatecategories', methods=['GET', 'POST'])
@role_required('admin')
def updatecategories():
    conn = get_db_connection()

    if request.method == 'POST':
        # Get the updated category name and ID from the form
        updated_category = request.form['category']
        category_id = request.form['category_id']

        # Update the category in the database
        conn.execute('UPDATE category SET name = ? WHERE Categoryid = ?', (updated_category, category_id))
        conn.commit()
        conn.close()
        flash('Category updated successfully!', 'success')
        return redirect(url_for('categories'))  # Redirect back to avoid form re-submission

    # Handle GET request
    category_id = request.args.get('category_id')  # Get the category ID (if any) from query parameters
    category = None  # Default value if no specific category is being edited

    if category_id:
        # Fetch the specific category for editing
        category = conn.execute('SELECT * FROM category WHERE Categoryid = ?', (category_id,)).fetchone()

    # Fetch all categories for the table
    categories = conn.execute('SELECT * FROM category').fetchall()
    conn.close()

    # Pass both the specific category and all categories to the template
    return render_template('UpdateCategory.html', category=category, categories=categories)


@app.route('/food', methods=['GET', 'POST'])
@role_required('admin')
def food():
    if request.method == 'POST':
        food_name = request.form['food']
        food_name1 = food_name.lower()
        conn1 = sqlite3.connect('event.db')
        conn1.row_factory = sqlite3.Row
        cursor = conn1.cursor()
        cursor.execute("SELECT * from foodtable where LOWER(foodname) = LOWER(?)",(food_name1,))
        food = cursor.fetchone()
        if food:
            flash("The food item already exists. Please insert new one!","danger")
            return redirect(url_for('food'))
        conn = get_db_connection()
        conn.execute('INSERT INTO foodtable (foodname) VALUES (?)', (food_name,))
        conn.commit()
        conn.close()
        flash("The new food is added successfully.","success")
        return redirect(url_for('food'))

    conn = get_db_connection()
    foods = conn.execute('SELECT * FROM foodtable').fetchall()
    conn.close()

    return render_template('foodlist.html', foods=foods)

@app.route('/delete_food/<int:foodid>', methods=['GET', 'POST'])
@role_required('admin')
def delete_food(foodid):
    conn = get_db_connection()
    conn.execute('DELETE FROM foodtable WHERE foodid = ?', (foodid,))
    conn.commit()
    conn.close()
    flash("Food is deleted successfully","success")
    return redirect(url_for('food'))

@app.route('/updatefood', methods=['GET', 'POST'])
@role_required('admin')
def updatefood():
    conn = get_db_connection()

    if request.method == 'POST':
        
        updated_food = request.form['food']
        foodid = request.form['food_id']
        food_name1 = updated_food.lower()
        conn1 = sqlite3.connect('event.db')
        conn1.row_factory = sqlite3.Row
        cursor = conn1.cursor()
        cursor.execute("SELECT * from foodtable where LOWER(foodname) = LOWER(?)",(food_name1,))
        food = cursor.fetchone()
        if food:
            flash("The food item already exists. Please change to new one!","danger")
            return redirect(url_for('food'))
        conn.execute('UPDATE foodtable SET foodname = ? WHERE foodid = ?', (updated_food, foodid))
        conn.commit()
        conn.close()
        flash("Food is updated successfully","success")
        return redirect(url_for('food')) 

    food_id = request.args.get('food_id')
    print(food_id)
    food = None  

    if food_id:
        food = conn.execute('SELECT * FROM foodtable WHERE foodid = ?', (food_id,)).fetchone()


    foods = conn.execute('SELECT * FROM foodtable').fetchall()
    conn.close()
    print(food)
    foodid = food['foodid']
    print(foodid)
    foodname = food['foodname']
    print(foodname)
    return render_template('foodupdate.html', food=food, foods=foods)


# Route to display sponsors
@app.route('/sponsorlist', methods=['GET', 'POST'])
@role_required('admin')
def sponsorlist():
    conn = sqlite3.connect('event.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        # Get form data
        sponsor_name = request.form['sponsorname']
        description = request.form['Description']
        photo = request.files['photo']

        if sponsor_name and description and photo:
            photo_file = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['upload_photo'], photo_file)
            photo.save(photo_path)
            photo_path = '\\' + photo_path

            # Insert sponsor into database
            cursor.execute("""
                INSERT INTO sponsor (name, image, Description)
                VALUES (?, ?, ?)
            """, (sponsor_name, photo_path, description))
            conn.commit()
            flash('Sponsor added successfully!', 'success')
        else:
            flash('Please fill out all fields and upload an image.', 'error')

    # Fetch all sponsors for the table
    cursor.execute("SELECT * FROM sponsor")
    sponsors = cursor.fetchall()
    
    searchdata = request.args.get('searchdata')
    if searchdata:
        cursor.execute("select * from sponsor where name like ?",(searchdata,))
        searchdata = cursor.fetchall()
        print(searchdata)
        return render_template('Sponsorlist.html', searchdata = searchdata)
    conn.close()

    return render_template('Sponsorlist.html', sponsors=sponsors)

# Delete sponsor route
@app.route('/deletesponsor/<int:sponsorid>', methods=['GET'])
@role_required('admin')
def deletesponsor(sponsorid):
    try:
        # Connect to the database
        connection = sqlite3.connect('event.db')
        cursor = connection.cursor()

        # Delete the sponsor from the database
        cursor.execute("DELETE FROM sponsor WHERE sponsorid = ?", (sponsorid,))
        connection.commit()

        # Log success
        print(f"Sponsor with ID {sponsorid} deleted successfully.")

    except sqlite3.Error as e:
        print(f"Error occurred while deleting sponsor: {e}")
    finally:
        # Close the database connection
        connection.close()

    # Redirect to the sponsor list page
    flash("Sponsor is deleted successfully","success")
    return redirect(url_for('sponsorlist'))

@app.route('/updatesponsor', methods=['GET', 'POST'])
@role_required('admin')
def updatesponsor():
    if request.method == 'POST':
        # Get form data
        sponsor_id = request.form.get('sponsorid')
        sponsor_name = request.form.get('sponsorname')
        description = request.form.get('Description')
        photo = request.files.get('photo')  # Changed to .get()
        
        # Save the uploaded photo if provided
        photo_path = None
        if photo and allowed_file(photo.filename):
            photo_file = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['upload_photo'], photo_file)
            photo.save(photo_path)
            photo_path = '\\' + photo_path
        
        # Update sponsor information in the database
        conn = sqlite3.connect('event.db')
        cursor = conn.cursor()
        
        if photo_path:
            query = """
                UPDATE sponsor 
                SET name = ?, Description = ?, image = ? 
                WHERE sponsorid = ?
            """
            cursor.execute(query, (sponsor_name, description, photo_path, sponsor_id))
        else:
            query = """
                UPDATE sponsor 
                SET name = ?, Description = ? 
                WHERE sponsorid = ?
            """
            cursor.execute(query, (sponsor_name, description, sponsor_id))
        
        conn.commit()
        conn.close()
        flash("Sponsor is updated successfully","success")
        return redirect(url_for('updatesponsor'))

    # Fetch all sponsors to display in the table
    conn = sqlite3.connect('event.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sponsor")
    sponsors = cursor.fetchall()
    conn.close()

    return render_template('UpdateSponsor.html', sponsors=sponsors)


@app.route('/contactsetting',  methods=['GET', 'POST'])
@role_required('admin')
def contactsetting():
    testid= 1
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM contactussetting where id=?",(testid,))
    setting = cursor.fetchone()
    Maintitle = setting['maintitle']
    id = setting['id']
    print(id)
    new_title = request.form.get('new-title')
    conn.commit()

    print(setting)
    print(Maintitle)
    return render_template('Contactussetting.html', setting = setting)


@app.route('/updatecontact/<id>', methods=['GET','POST'])
@role_required('admin')
def updatecontact(id):
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    new_title = request.form.get('new-title')
    second_title = request.form.get('second-title')
    paragraph = request.form.get('paragraph')
    phone = request.form.get('phone')
    email = request.form.get('email')
    location = request.form.get('location')
    print(new_title)
    if new_title:
        cursor.execute("update contactussetting set maintitle=? where id=?",(new_title, id))
    if second_title:
         cursor.execute("update contactussetting set secondtitle=? where id=?",(second_title, id))
    if paragraph:
         cursor.execute("update contactussetting set paragraph=? where id=?",(paragraph, id))
    if phone:
         cursor.execute("update contactussetting set phone=? where id=?",(phone, id))
    if email:
         cursor.execute("update contactussetting set email=? where id=?",(email, id))
    if location:
         cursor.execute("update contactussetting set location=? where id=?",(location, id))
    conn.commit()

    return redirect(url_for('contactsetting'))



@app.route('/aboutsetting',  methods=['GET', 'POST'])
@role_required('admin')
def aboutsetting():
    testid= 1
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM aboutussetting where id=?",(testid,))
    setting = cursor.fetchone()
    firsttitle= setting['firsttitle']
    print(setting)
    print(firsttitle)
    conn.commit()
    print(setting)
    return render_template('Aboutussetting.html', setting = setting)

@app.route('/updateabout/<id>', methods=['GET','POST'])
@role_required('admin')
def updateabout(id):
    testid= 1
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM aboutussetting WHERE id = ?", (testid,))
    settingpart = cursor.fetchone()
    firsttitle = request.form.get('firsttitle')
    secondtitle = request.form.get('secondtitle')
    firstsmalltitle= request.form.get('firstsmalltitle')
    firstsmallparagraph= request.form.get('firstsmallparagraph')
    secondsmalltitle= request.form.get('secondsmalltitle')
    secondsmallparagraph= request.form.get('secondsmallparagraph')
    photo = request.files.get('photo')
    servicetitle1 = request.form.get('servicetitle1')
    servicetitle2 = request.form.get('servicetitle2')
    card1title = request.form.get('card1title')
    card1second = request.form.get('card1second')
    card1photo = request.files.get('photo1')
    card2title = request.form.get('card2title')
    card2second = request.form.get('card2second')
    card2photo = request.files.get('card2photo')
    card3title = request.form.get('card3title')
    card3second = request.form.get('card3second')
    card3photo = request.files.get('card3photo')
    card4title = request.form.get('card4title')
    card4second = request.form.get('card4second')
    card4photo = request.files.get('card4photo')
    if firsttitle or secondtitle:
        cursor.execute("update aboutussetting set firsttitle=?, secondtitle=? where id=?",(firsttitle, secondtitle, id))
    if firstsmalltitle or firstsmallparagraph:
        cursor.execute("update aboutussetting set firstsmalltitle=?, firstsmallparagraph=? where id=?",(firstsmalltitle, firstsmallparagraph, id))
    if secondsmalltitle or secondsmallparagraph:
        cursor.execute("update aboutussetting set secondsmalltitle=?, secondsmallparagraph=? where id=?",(secondsmalltitle, secondsmallparagraph, id))
    print(photo)
    if photo and allowed_file(photo.filename):
        photo_file = secure_filename(photo.filename)
        photo_path = os.path.join(app.config['upload_photo'],photo_file)
        photo.save(photo_path)
        photo_path ='\\'+photo_path
        print(photo_path)
        cursor.execute("update aboutussetting set photo=? where id=?",(photo_path, id))
    if servicetitle1 and servicetitle2:
        cursor.execute("update aboutussetting set servicetitle1=?, servicetitle2=? where id=?",(servicetitle1, servicetitle2, id))
    if card1title or card1second:
        if card1photo and allowed_file(card1photo.filename):
            photo_file = secure_filename(card1photo.filename)
            print(photo_file)
            photo_path = os.path.join(app.config['upload_photo'],photo_file)
            print(photo_path)
            card1photo.save(photo_path)
            photo_path ='\\'+photo_path 
            cursor.execute("update aboutussetting set card1title=?, card1second=?, card1photo=? where id=?",(card1title, card1second, photo_path, id))
        else:
            # If no new photo, keep the existing one
            photo_path = settingpart['card1photo']
            cursor.execute("update aboutussetting set card1title=?, card1second=?, card1photo=? where id=?",(card1title, card1second, photo_path, id))
    if card2title or card2second:
        if card2photo and allowed_file(card2photo.filename):
            photo_file = secure_filename(card2photo.filename)
            print(photo_file)
            photo_path = os.path.join(app.config['upload_photo'],photo_file)
            print(photo_path)
            card2photo.save(photo_path)
            photo_path ='\\'+photo_path
            cursor.execute("update aboutussetting set card2title=?, card2second=?, card2photo=? where id=?",(card2title, card2second, photo_path, id))
        else:
            photo_path = settingpart['card2photo']
            cursor.execute("update aboutussetting set card2title=?, card2second=?, card2photo=? where id=?",(card2title, card2second, photo_path, id))
    if card3title or card3second:
        if card3photo and allowed_file(card3photo.filename):
            photo_file = secure_filename(card3photo.filename)
            print(photo_file)
            photo_path = os.path.join(app.config['upload_photo'],photo_file)
            print(photo_path)
            card3photo.save(photo_path)
            photo_path ='\\'+photo_path
            cursor.execute("update aboutussetting set card3title=?, card3second=?, card3photo=? where id=?",(card3title, card3second, photo_path, id))
        else:
            photo_path = settingpart['card3photo']
            cursor.execute("update aboutussetting set card3title=?, card3second=?, card3photo=? where id=?",(card3title, card3second, photo_path, id))
    if card4title or card4second:
        if card4photo and allowed_file(card4photo.filename):
            photo_file = secure_filename(card4photo.filename)
            print(photo_file)
            photo_path = os.path.join(app.config['upload_photo'],photo_file)
            print(photo_path)
            card4photo.save(photo_path)
            photo_path ='\\'+photo_path
            cursor.execute("update aboutussetting set card4title=?, card4second=?, card4photo=? where id=?",(card4title, card4second, photo_path, id))
        else:
            photo_path = settingpart['card4photo']
            cursor.execute("update aboutussetting set card4title=?, card4second=?, card4photo=? where id=?",(card4title, card4second, photo_path, id))
    conn.commit()

    return redirect(url_for('aboutsetting'))


@app.route('/dashboardsetting',  methods=['GET', 'POST'])
@role_required('admin')
def dashboardsetting():
    sponsorlist2 = []
    testid= 1
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dashboard where id=?",(testid,))
    setting = cursor.fetchone()
    cursor.execute("SELECT * from aboutussetting where id=?", (testid,))
    setting2 = cursor.fetchone()
    cursor.execute("SELECT * from event")
    eventlist = cursor.fetchall()
    cursor.execute("SELECT * FROM sponsor")
    sponsorlist1 = cursor.fetchall()
    for sponsor in sponsorlist1:
        conn = sqlite3.connect('event.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        sponsorid = sponsor['sponsorid']
        cursor.execute("select name from sponsor where sponsorid=?", (sponsorid,))
        sponsorname = cursor.fetchone()
        sponsorlist2.append(sponsorname)
    events_with_sponsors = []
    print(sponsorlist2)
# Combine events and sponsors
    for event, sponsor in zip(eventlist, sponsorlist2):
        events_with_sponsors.append({
            'event': event,
            'sponsor': sponsor
        })
    return render_template('Dashboardsetting.html', setting = setting, setting2 = setting2, events_with_sponsors=events_with_sponsors, sponsorlist1 = sponsorlist1)


@app.route('/updatedashboard/<id>', methods=['GET','POST'])
@role_required('admin')
def updatedashboard(id):
    testid= 1
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("select * from dashboard where id=?",(testid,))
    dashboard = cursor.fetchone()
    photo_path = dashboard['upperphoto']
    firsttitle = request.form.get('firsttitle')
    secondtitle = request.form.get('secondtitle')
    thirdtitle = request.form.get('thirdtitle')
    upperphoto = request.files.get('upperphoto')
    aboutfirsttitle = request.form.get('aboutfirsttitle')
    aboutsecondtitle = request.form.get('aboutsecondtitle')
    eventtitle = request.form.get('eventtitle')
    eventsecont = request.form.get('eventsecont')
    newstitle = request.form.get('newstitle')
    newssecond = request.form.get('newssecond')
    news1photo = request.files.get('news1photo')
    news1name = request.form.get('news1name')
    news1link = request.form.get('news1link')
    news2photo = request.files.get('news2photo')
    news2name = request.form.get('news2name')
    news2link = request.form.get('news2link')
    news3photo = request.files.get('news3photo')
    news3name = request.form.get('news3name')
    news3link = request.form.get('news3link')
    supporterfirst = request.form.get('supporterfirst')
    supportersecond = request.form.get('supportersecond')
    
    if firsttitle or secondtitle or thirdtitle:
         if upperphoto and allowed_file(upperphoto.filename):
            photo_file = secure_filename(upperphoto.filename)
            print(photo_file)
            photo_path = os.path.join(app.config['upload_photo'],photo_file)
            print(photo_path)
            upperphoto.save(photo_path)
            photo_path ='\\'+photo_path
            cursor.execute("update dashboard set firsttitle=?, secondtitle=?, thirdtitle=?, upperphoto=? where id=?",(firsttitle, secondtitle, thirdtitle, photo_path, id))
         else:
             cursor.execute("update dashboard set firsttitle=?, secondtitle=?, thirdtitle=?, upperphoto=? where id=?",(firsttitle, secondtitle, thirdtitle, photo_path, id))
    if aboutfirsttitle or aboutsecondtitle:
        cursor.execute("update dashboard set aboutfirsttitle=?, aboutsecondtitle=? where id=?",(aboutfirsttitle, aboutsecondtitle, id))
    if eventtitle or eventsecont:
        cursor.execute("update dashboard set eventtitle=?, eventsecont=? where id=?",(eventtitle, eventsecont, id))
    if newstitle or newssecond:
        cursor.execute("update dashboard set newstitle=?, newssecond=? where id=?",(newstitle, newssecond, id))
    if news1name or news1link:
        if news1photo and allowed_file(news1photo.filename):
            photo_file = secure_filename(news1photo.filename)
            print(photo_file)
            photo_path = os.path.join(app.config['upload_photo'],photo_file)
            print(photo_path)
            news1photo.save(photo_path)
            photo_path ='\\'+photo_path
            cursor.execute("update dashboard set news1photo=?, news1name=?, news1link=? where id=?",(photo_path, news1name, news1link, id))
    if news2name or news2link:
        if news2photo and allowed_file(news2photo.filename):
            photo_file = secure_filename(news2photo.filename)
            print(photo_file)
            photo_path = os.path.join(app.config['upload_photo'],photo_file)
            print(photo_path)
            news2photo.save(photo_path)
            photo_path ='\\'+photo_path
            cursor.execute("update dashboard set news2photo=?, news2name=?, news2link=? where id=?",(photo_path, news2name, news2link, id))
    if news3name or news3link:
        if news3photo and allowed_file(news3photo.filename):
            photo_file = secure_filename(news3photo.filename)
            print(photo_file)
            photo_path = os.path.join(app.config['upload_photo'],photo_file)
            print(photo_path)
            news3photo.save(photo_path)
            photo_path ='\\'+photo_path
            cursor.execute("update dashboard set news3photo=?, news3name=?, news3link=? where id=?",(photo_path, news3name, news3link, id))
            
    if supporterfirst or supportersecond:
        cursor.execute("update dashboard set supporterfirst=?, supportersecond=? where id=?",(supporterfirst, supportersecond, id))
        
        
    conn.commit()
    
    return redirect(url_for('dashboardsetting'))


# Route for listing events
@app.route('/eventlist')
@role_required('admin')
def eventlist():
    # Connect to the database
    conn = sqlite3.connect('event.db')
    cursor = conn.cursor()
    
    # Fetch event data
    query = """
        SELECT event.eventid, event.name, event.image, event.detail, event.date, event.time, sponsor.name, event.price, event.totalpersons, event.food
        FROM event
        LEFT JOIN sponsor ON event.sponsorid = sponsor.sponsorid
    """
    cursor.execute(query)
    events = cursor.fetchall()
    searchdata = request.args.get('searchdata')
    if searchdata:
        cursor.execute("select * from users where username like ?",(searchdata,))
        searchdata = cursor.fetchall()
        formatted_events = []
        for event in events:
            event_id, name, image, detail, date, time, sponsor_name, price, totalpersons, food = event
            conn1 = sqlite3.connect('event.db')
            conn1.row_factory = sqlite3.Row
            cursor1 = conn1.cursor()
            cursor1.execute("select * from foodtable where foodid=?",(food,))
            food = cursor1.fetchone()
            if food:
                foodname = food['foodname']
            else:
                foodname = "Not Available"
            if time:  # Check if the time value exists
                try:
                    time_12hr = datetime.strptime(time, '%H:%M:%S').strftime('%I:%M %p')  # Convert to 12-hour format
                except ValueError:
                    time_12hr = time  # Use original value if the format is unexpected
            else:
                time_12hr = "N/A"  # Handle missing time values
        formatted_events.append((event_id, name, image, detail, date, time_12hr, sponsor_name, price, totalpersons, foodname))
        return render_template('eventlist.html', events=formatted_events)
    conn.close()
    
    # Convert time to 12-hour format with AM/PM
    formatted_events = []
    foodlist = []
    for event in events:

        event_id, name, image, detail, date, time, sponsor_name, price, totalpersons, food = event
        conn1 = sqlite3.connect('event.db')
        conn1.row_factory = sqlite3.Row
        cursor1 = conn1.cursor()
        cursor1.execute("select * from foodtable where foodid=?",(food,))
        food = cursor1.fetchone()
        if food:
            foodname = food['foodname']
        else:
            foodname = "Not Available"
        
        if time:  # Check if the time value exists
            try:
                time_12hr = datetime.strptime(time, '%H:%M:%S').strftime('%I:%M %p')  # Convert to 12-hour format
            except ValueError:
                time_12hr = time  # Use original value if the format is unexpected
        else:
            time_12hr = "N/A"  # Handle missing time values
        formatted_events.append((event_id, name, image, detail, date, time_12hr, sponsor_name, price, totalpersons, foodname))
    
    # Pass formatted data to the template
    return render_template('eventlist.html', events=formatted_events)
@app.route('/eventlist1')
@role_required('admin')
def eventlist1():
    # Connect to the database
    conn = sqlite3.connect('event.db')
    cursor = conn.cursor()
    
    # Fetch event data
    query = """
        SELECT event.eventid, event.name, event.image, event.detail, event.date, event.totalpersons, event.price, event.time, sponsor.name
        FROM event
        LEFT JOIN sponsor ON event.sponsorid = sponsor.sponsorid
    """
    cursor.execute(query)
    events = cursor.fetchall()
    searchdata = request.args.get('searchdata')
    if searchdata:
        cursor.execute("select * from users where username like ?",(searchdata,))
        searchdata = cursor.fetchall()
        formatted_events = []
        for event in events:
            event_id, name, image, detail, date, time, sponsor_name = event
            if time:  # Check if the time value exists
                try:
                    time_12hr = datetime.strptime(time, '%H:%M:%S').strftime('%I:%M %p')  # Convert to 12-hour format
                except ValueError:
                    time_12hr = time  # Use original value if the format is unexpected
            else:
                time_12hr = "N/A"  # Handle missing time values
        formatted_events.append((event_id, name, image, detail, date, time_12hr, sponsor_name))
        return render_template('eventlist.html', events=formatted_events)
    conn.close()
    
    # Convert time to 12-hour format with AM/PM
    formatted_events = []
    for event in events:
        event_id, name, image, detail, date, time, sponsor_name = event
        if time:  # Check if the time value exists
            try:
                time_12hr = datetime.strptime(time, '%H:%M:%S').strftime('%I:%M %p')  # Convert to 12-hour format
            except ValueError:
                time_12hr = time  # Use original value if the format is unexpected
        else:
            time_12hr = "N/A"  # Handle missing time values
        formatted_events.append((event_id, name, image, detail, date, time_12hr, sponsor_name))
    
    # Pass formatted data to the template
    return render_template('eventlist.html', events=formatted_events)

@app.route('/eventadd', methods=['GET', 'POST'])
@role_required('admin')
def eventadd():
    if request.method == 'GET':
        try:
            conn = sqlite3.connect('event.db')
            cursor = conn.cursor()
            # Fetch sponsors and categories
            cursor.execute("SELECT sponsorid, name FROM sponsor")
            sponsors = cursor.fetchall()  # List of tuples (sponsorid, name)
            cursor.execute("SELECT categoryid, name FROM category")
            categories = cursor.fetchall()  # List of tuples (categoryid, name)
            cursor.execute("SELECT * FROM foodtable")
            foods = cursor.fetchall()  # List of tuples (categoryid, name)
        except sqlite3.Error as e:
            flash(f"Database error: {e}", "danger")
            sponsors, categories, foods = [], [], []
        finally:
            if conn:
                conn.close()
        return render_template('Eventadd.html', sponsors=sponsors, categories=categories, foods= foods)

    elif request.method == 'POST':
        conn = None  # Initialize conn to None
        try:
            # Retrieve form data
            event_name = request.form['category']
            event_type = request.form['eventtype']
            description = request.form['description']
            date = request.form['date']
            time = request.form['time']
            price = request.form['price']
            food = request.form['food']
            person = request.form['person']
            sponsor_id = request.form['artisttype']
            photo = request.files['photo']

            # Convert time to 12-hour format
            time_24hr_obj = datetime.strptime(time, '%H:%M')
            time_12hr = time_24hr_obj.strftime('%I:%M %p')

            # Handle the uploaded image file
            photo_filename = None
            if photo and allowed_file(photo.filename):
                photo_file = secure_filename(photo.filename)
                photo_path = os.path.join(app.config['upload_photo'], photo_file)
                photo.save(photo_path)
                photo_path = '\\' + photo_path

            # Insert event into the database
            conn = sqlite3.connect('event.db')
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO event (name, detail, date, time, image, price, totalpersons, food, categoryid, sponsorid)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (event_name, description, date, time_12hr, photo_path, price, person, food, event_type, sponsor_id))
            conn.commit()

            flash('Event added successfully!', 'event_success')
        except sqlite3.Error as e:
            flash(f"Database error: {e}", "danger")
            if conn:
                conn.rollback()
        except Exception as e:
            flash(f"Unexpected error: {e}", "danger")
        finally:
            if conn:
                conn.close()

        return redirect(url_for('eventadd'))


# Create a custom filter to format the time
@app.template_filter('format_time')
def format_time(value):
    if value:
        try:
            # Assuming the time is in 24-hour format (HH:MM), e.g., "14:30"
            time_obj = datetime.strptime(value, '%H:%M')
            return time_obj.strftime('%I:%M %p')  # 12-hour format with AM/PM
        except ValueError:
            return value
    return value

# Function to convert 12-hour format to 24-hour format
def convert_to_24hr_format(time_str):
    try:
        # Assuming the time is in 'hh:mm AM/PM' format
        time_obj = datetime.strptime(time_str, '%I:%M %p')  # 12-hour format with AM/PM
        return time_obj.strftime('%H:%M')  # 24-hour format
    except ValueError:
        return time_str  # Return original value if format is incorrect

from datetime import datetime

@app.route('/eventupdate/<int:event_id>', methods=['GET', 'POST'])
@role_required('admin')
def eventupdate(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the event details
    cursor.execute("SELECT * FROM event WHERE eventid = ?", (event_id,))
    event = cursor.fetchone()
    foodname = ''
    food = event['food']
    cursor.execute("select foodname from foodtable where foodid=?",(food,))
    food1 = cursor.fetchone()
    foodname = food1   

    if event is None:
        flash("Event not found", "error")
        return redirect(url_for('eventlist'))

    # Convert the time from 12-hour format to 24-hour format
    def convert_to_24hr_format(time_str):
        try:
            time_obj = datetime.strptime(time_str, '%I:%M %p')  # Convert from 12-hour format
            return time_obj.strftime('%H:%M')  # Return 24-hour format
        except ValueError:
            return time_str  # In case of an invalid time format, return it as is

    event_time_24hr = convert_to_24hr_format(event['Time'])  # Converted time

    # Fetch categories and sponsors for the dropdown lists
    cursor.execute("SELECT * FROM category")
    categories = cursor.fetchall()

    cursor.execute("SELECT * FROM sponsor")
    sponsors = cursor.fetchall()
    
    cursor.execute("SELECT * FROM foodtable")
    foods = cursor.fetchall()

    conn.close()

    if request.method == 'POST':
        event_name = request.form['category']
        description = request.form['description']
        event_type = request.form['eventtype']
        event_date = request.form['date']
        event_time = request.form['time']  # The updated time
        price = request.form['price']
        food = request.form['food']
        person = request.form['person']
        sponsor_id = request.form['sponsor']
        photo = request.files['photo']
        
        # Convert time to 12-hour format for saving to database
        time_24hr_obj = datetime.strptime(event_time, '%H:%M')
        time_12hr = time_24hr_obj.strftime('%I:%M %p')
            
        # If a new photo is uploaded, save it
        if photo and allowed_file(photo.filename):
                photo_file = secure_filename(photo.filename)
                photo_path = os.path.join(app.config['upload_photo'], photo_file)
                photo.save(photo_path)
                photo_path = '\\' + photo_path
        else:
            # If no new photo, keep the existing one
            photo_path = event['image']

        # Update the event in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(""" 
            UPDATE event
            SET name = ?, detail = ?, categoryid = ?, date = ?, Time = ?, price = ?, food = ?, totalpersons=?, image = ?, sponsorid = ?
            WHERE eventid = ?
        """, (event_name, description, event_type, event_date, time_12hr, price, food, person, photo_path, sponsor_id, event_id))
        conn.commit()
        conn.close()

        flash("Event updated successfully", "event_success")
        return redirect(url_for('eventlist'))

    return render_template('EventUpdate.html', event=event, event_time=event_time_24hr, categories=categories, sponsors=sponsors, foodname = foodname, foods = foods)


@app.route('/eventdelete/<int:event_id>', methods=['GET'])
@role_required('admin')
def eventdelete(event_id):
    try:
        # Connect to the database
        conn = sqlite3.connect('event.db')
        cursor = conn.cursor()

        # Fetch the event's image path to delete it from the filesystem
        cursor.execute("SELECT image FROM event WHERE eventid = ?", (event_id,))
        event = cursor.fetchone()
        if event and event[0]:  # If an image exists
            image_path = os.path.join('static/photo', event[0])
            if os.path.exists(image_path):
                os.remove(image_path)

        # Delete the event from the database
        cursor.execute("DELETE FROM event WHERE eventid = ?", (event_id,))
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Error deleting event: {e}")
    finally:
        conn.close()
    flash("Event is deleted successfully","event_success")
    return redirect(url_for('eventlist'))  # Redirect back to the event list

@app.route('/requestedbooking')
@role_required('admin')
def requestedbooking():
    eventnamelist = []
    event_with_requested = []
    conn = sqlite3.connect('event.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM requestbooking")
    requestedbookings = cursor.fetchall()
    for request in requestedbookings:
        eventid = request['eventid']
        cursor.execute("select name from event where eventid=?",(eventid,))
        eventname = cursor.fetchone()
        eventnamelist.append(eventname)
    for requested, event in zip(requestedbookings, eventnamelist):
        event_with_requested.append({
            'event': event,
            'requested': requested
        })
    return render_template('RequestedBooking.html', requestedbookings = requestedbookings, event_with_requested = event_with_requested)


@app.route('/confirm_booking/<int:bookingid>', methods=['POST'])
@role_required('admin')
def confirm_booking(bookingid):
    try:
        conn = sqlite3.connect('event.db')
        conn.row_factory = sqlite3.Row  # Enable dictionary-like access
        cursor = conn.cursor()
        
        # Retrieve the booking details from the `requestbooking` table
        cursor.execute("SELECT * FROM requestbooking WHERE bookingid = ?", (bookingid,))
        requested_booking = cursor.fetchone()
        
        if requested_booking:
            # Insert the booking into the `bookingtable` table
            cursor.execute("""
                INSERT INTO bookingtable (userid, eventid, name, phone, email, address, totalperson, message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                requested_booking['userid'], requested_booking['eventid'], requested_booking['name'],
                requested_booking['phone'], requested_booking['email'], requested_booking['address'],
                requested_booking['totalperson'], requested_booking['message']
            ))
            
            # Delete the booking from the `requestbooking` table
            cursor.execute("DELETE FROM requestbooking WHERE bookingid = ?", (bookingid,))
            
            conn.commit()
            flash("Booking confirmed successfully.", "success")
        else:
            flash("Requested booking not found.", "error")
    
    except sqlite3.Error as e:
        flash(f"An error occurred: {e}", "error")
    finally:
        conn.close()
    
    return redirect(url_for('requestedbooking'))

@app.route('/delete_for_confirm/<int:bookingid>', methods=['POST'])
@role_required('admin')
def delete_for_confirm(bookingid):
    try:
        conn = sqlite3.connect('event.db')
        cursor = conn.cursor()
        
        # Delete the booking from the `requestbooking` table
        cursor.execute("DELETE FROM requestbooking WHERE bookingid = ?", (bookingid,))
        conn.commit()
        
        flash("Requested booking deleted successfully.", "success")
    except sqlite3.Error as e:
        flash(f"An error occurred: {e}", "error")
    finally:
        conn.close()
    
    return redirect(url_for('requestedbooking'))


@app.route('/changepassword', methods=['GET', 'POST'])
def changepassword():
    if request.method == 'POST':
        email = request.form['email']
        oldpassword = request.form['oldpassword']
        conn = sqlite3.connect('event.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password, type FROM users WHERE email=?', (email,))
        user = cursor.fetchone()

        if user:
            password, user_type = user
            if check_password_hash(password, oldpassword):
                newpassword = request.form['newpassword']
                confirmpassword = request.form['confirmpassword']
                if newpassword == confirmpassword:
                    if not is_strong_password(newpassword):
                        flash("Password is not a strong password.","danger")
                        return redirect('changepassword')
                    else:
                        hashed_password = generate_password_hash(newpassword)
                        conn.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
                        conn.commit()  # Ensure the changes are committed
                        flash("Password updated successfully!", "success")
                        conn.close()
                        return redirect(url_for('Login'))

                else:
                    flash("Please enter same passwords for New Password and Confirm Password","danger")
                    return redirect(url_for('changepassword'))
            else:
                flash('Email and Password are not correct', 'danger')
                return redirect(url_for('changepassword'))
        else:
            flash('Email and Password are not correct', 'danger')
            return redirect(url_for('changepassword'))
    return render_template('Change_password.html')


@app.route('/eventbycategory/<Categoryid>')
def eventbycategory(Categoryid):
    try:
        connection = sqlite3.connect("music.db")
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        return redirect(url_for("event", Categoryid = Categoryid))
    except Exception as e:
        print(type(e).__name__)
        return "none"
   

@app.errorhandler(404)
def page_not_found(error):
    flash("Your route doesn't exit", 'danger')
    return redirect(url_for('dashboard'))
    
if __name__ == "__main__":
    app.run(debug=True, port=5003)