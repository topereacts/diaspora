import os
from cs50 import SQL
from flask import Flask, flash, render_template, request, redirect, session, url_for
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from helpers import login_required, get_interested_count

app = Flask(__name__)

# Set absolute path for saving the uploaded files
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'img')  # Ensure it's in the static folder for Flask to serve
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///errand.db")

@app.route("/")
@login_required
def index():
    # Check the user's role and render the appropriate dashboard
    if session.get("role") == "errander":
        return redirect(url_for("errander_dashboard"))
    elif session.get("role") == "errandee":
        return redirect(url_for("errandee_dashboard"))
    else:
        flash("Unknown user role")
        return redirect(url_for("login"))  # Redirect to login if role is not recognized


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        # Collect form data
        username = request.form.get("username")
        fullname = request.form.get("fullname")
        gender = request.form.get("gender")
        country = request.form.get("country")
        address = request.form.get("address")
        phonenumber = request.form.get("phonenumber")
        whatsappnumber = request.form.get("whatsappnumber")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        role = request.form.get("role")

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match")
            return render_template("register.html")

        # Check if a file is uploaded
        file = request.files.get('profile_picture')
        if file and file.filename == '':
            flash("No selected file")
            return render_template("register.html")

        # Handle file upload
        file = request.files['profile_picture']
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            
            # Absolute path for saving the file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Ensure the directory exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

            # Save the file to the absolute path
            file.save(file_path)

            # Store the relative path for use in templates
            # Ensure the file path uses forward slashes (/) instead of backslashes (\)
            profile_picture_path = os.path.join('img', filename).replace("\\", "/")  # Ensures forward slashes


        try:
            # Check if username is already taken
            existing_user = db.execute("SELECT * FROM users WHERE username = ?", username)
            if existing_user:
                flash("Username already taken")
                return render_template("register.html")

            # Hash the password
            hashed_password = generate_password_hash(password)

            # Insert the new user into the database
            db.execute(
                "INSERT INTO users (fullname, username, gender, country, address, phonenumber, whatsappnumber, password, role, profile_picture) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                fullname, username, gender, country, address, phonenumber, whatsappnumber, hashed_password, role, profile_picture_path
            )

            flash("Registration successful")
            return redirect(url_for('login'))

        except db.Error as e:
            flash(f"Database error: {e}")
            return render_template("register.html")
    else:
        return render_template("register.html")

    
@app.route("/login", methods=["POST", "GET"])
def login():
    # Check if user is already logged in
    if "user_id" in session:
        # Redirect based on user role
        if session["role"] == "errander":
            return redirect(url_for("errander_dashboard", username=session["username"]))
        elif session["role"] == "errandee":
            return redirect(url_for("errandee_dashboard", username=session["username"]))

    
    # If not logged in, proceed with login process
    if request.method == "POST":
        # Retrieve the username and password
        username = request.form.get("username")
        password = request.form.get("password")

        # Query the database for the user
        user = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Check if user exists and password matches
        if len(user) != 1 or not check_password_hash(user[0]["password"], password):
            flash("Invalid username or password")
            return render_template("login.html")

        # Store user info in session
        session["user_id"] = user[0]["id"]
        session["username"] = user[0]["username"]
        session["role"] = user[0]["role"]  # Store user role in session

        # Redirect based on user role
        if user[0]["role"] == "errander":
            return redirect (url_for("errander_dashboard"))
        elif user[0]["role"] == "errandee":
            return redirect (url_for("errandee_dashboard"))


    # If GET request, render the login form
    return render_template("login.html")


@app.route("/errander_dashboard")
@login_required
def errander_dashboard():
    # Get the current user's errands
    errands = db.execute("SELECT * FROM errands WHERE user_id = ?", session["user_id"])

    user_id = session["user_id"]
    interested_count = get_interested_count(user_id)
    
    # Calculate the number of interested errandees
    # interested_count = sum(
    #     1 for errand in errands 
    #     for interest in db.execute("SELECT COUNT(*) as count FROM interested_errands WHERE errand_id = ?", errand['id'])
    #     if interest['count'] > 0
    # )

    # Fetch interested errandees for the errands posted by the errander
    errander_id = session["user_id"]
    interested_errandees = db.execute("""
        SELECT u.fullname, u.profile_picture, u.country, u.whatsappnumber, u.phonenumber, u.errands_done, ie.errand_id, ie.request_status, u.id AS id
        FROM interested_errands ie
        JOIN users u ON u.id = ie.errandee_id
        JOIN errands e ON e.id = ie.errand_id
        WHERE e.user_id = ? AND e.status = 'open'
    """, errander_id)

    # Update interested count by excluding completed errands
    interested_count = db.execute("""
        SELECT COUNT(*)
        FROM interested_errands ie
        JOIN errands e ON e.id = ie.errand_id
        WHERE e.user_id = ? AND e.status = 'open'
    """, errander_id)[0]["COUNT(*)"]

    # Calculate the number of interested errandees
    interested_count = len(interested_errandees)
    
    # Fetch the profile picture of the current user
    user = db.execute("SELECT profile_picture FROM users WHERE id = ?", session["user_id"])
    profile_picture = user[0]["profile_picture"] if user else None

    # Get the current page from the query parameters, default to 1 if not provided
    page = request.args.get("page", 1, type=int)
    errands_per_page = 3
    offset = (page - 1) * errands_per_page

    # Fetch open errands
    open_errands = db.execute("""
        SELECT e.*, u.fullname, u.country
        FROM errands e
        JOIN users u ON u.id = e.user_id
        WHERE e.user_id = ? AND e.status = 'open'
    """, user_id)

    # Fetch completed errands
    completed_errands = db.execute("""
        SELECT e.*, u.fullname, u.country, e.completion_date
        FROM errands e
        JOIN users u ON u.id = e.user_id
        WHERE e.user_id = ? AND e.status = 'completed'
        ORDER BY completion_date DESC
        LIMIT ? OFFSET ?
    """, user_id, errands_per_page, offset)

    # Count total completed errands for pagination
    total_errands = db.execute(
        "SELECT COUNT(*) FROM errands WHERE user_id = ? AND status = 'completed'",
        user_id
    )[0]["COUNT(*)"]
    total_pages = (total_errands + errands_per_page - 1) // errands_per_page


    return render_template("errander_dashboard.html", username=session["username"], errands=errands, profile_picture=profile_picture, interested_count=interested_count, 
                           open_errands=open_errands, completed_errands=completed_errands, page=page, total_pages=total_pages,
                           errandees=interested_errandees)


@app.route("/errandee_dashboard", methods=["GET"])
@login_required
def errandee_dashboard():
    user_id = session["user_id"]
    interested_count = get_interested_count(user_id)
    # Fetch all open errands along with the errander's details
    errands = db.execute("""
        SELECT e.id, e.description, e.location, e.status, 
               u.fullname, u.country, u.profile_picture 
        FROM errands e
        JOIN users u ON e.user_id = u.id
        WHERE e.status = 'open'
    """)

    # Create a set of errand ids that the current errandee has expressed interest in
    interested_errands = db.execute("SELECT errand_id FROM interested_errands WHERE errandee_id = ?", session["user_id"])
    interested_errand_ids = {interest['errand_id'] for interest in interested_errands}

    # Get the number of interested errandees for each errand
    for errand in errands:
        errand['interested_count'] = db.execute("SELECT COUNT(*) FROM interested_errands WHERE errand_id = ?", errand['id'])[0]['COUNT(*)']
        # Add a field to indicate if the current errandee has expressed interest
        errand['is_requested'] = errand['id'] in interested_errand_ids

    #notification for errandee
    #notifications = db.execute("""
        #SELECT message FROM notifications
        #WHERE errandee_id = ? AND status = 'unread'
    #""", user_id) 

    # Fetch notifications for the errandee
    notifications = db.execute("""
        SELECT * FROM notifications WHERE errandee_id = ? AND is_viewed = FALSE
    """, user_id)

    # Mark notifications as viewed
    db.execute("""
        UPDATE notifications SET is_viewed = TRUE WHERE errandee_id = ?
    """, user_id)

    # Fetch the profile picture of the current user
    user = db.execute("SELECT profile_picture FROM users WHERE id = ?", session["user_id"])
    profile_picture = user[0]["profile_picture"] if user else None
    return render_template("errandee_dashboard.html", errands=errands, username=session["username"], profile_picture=profile_picture, 
                           interested_count=interested_count, notifications=notifications)


@app.route("/create_errand", methods=["POST", "GET"])
@login_required
def create_errand():
    user_id = session["user_id"]
    interested_count = get_interested_count(user_id)

    if request.method == "POST":
        # Get the form data
        description = request.form.get("description")
        location = request.form.get("location")
        
        # Get the errander's profile picture from the session (assuming it's stored)
        profile_picture = session.get("profile_picture")

        # Insert the errand into the database
        db.execute("INSERT INTO errands (user_id, description, location, status, profile_picture) VALUES (?, ?, ?, ?, ?)",
                session["user_id"], description, location, "open", profile_picture)
        
        flash(f"Errand created successfully!")
        return redirect(url_for("errander_dashboard"))
    
    return render_template("send_errand.html", interested_count=interested_count)


@app.route("/edit_errand/<int:errand_id>", methods=["GET", "POST"])
@login_required
def edit_errand(errand_id):
    user_id = session["user_id"]
    interested_count = get_interested_count(user_id)
    if request.method == "POST":
        new_description = request.form.get("description")
        new_location = request.form.get("location")

        db.execute("UPDATE errands SET description = ?, location = ? WHERE id = ? AND user_id = ?",
                   new_description, new_location, errand_id, session["user_id"])
        flash(f"Errand updated successfully!")
        return redirect(url_for("errander_dashboard"))
    
    # Retrieve errand details for editing
    errand = db.execute("SELECT * FROM errands WHERE id = ? AND user_id = ?", errand_id, session["user_id"])
    return render_template("edit_errand.html", errand=errand[0], interested_count=interested_count)


@app.route("/delete_errand/<int:errand_id>")
@login_required
def delete_errand(errand_id):
    db.execute("DELETE FROM errands WHERE id = ? AND user_id = ?", errand_id, session["user_id"])
    flash(f"Errand deleted successfully!")
    return redirect(url_for("errander_dashboard"))


@app.route("/complete_errand/<int:errand_id>")
@login_required
def complete_errand(errand_id):
    db.execute("UPDATE errands SET status = 'completed', completion_date = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?", errand_id, session["user_id"])
    flash(f"Errand marked as completed!")
    return redirect(url_for("errander_dashboard"))


@app.route("/express_interest/<int:errand_id>")
@login_required
def express_interest(errand_id):
    # Check if the user has already expressed interest
    existing_interest = db.execute("SELECT * FROM interested_errands WHERE errand_id = ? AND errandee_id = ?", errand_id, session["user_id"])

    if not existing_interest:
        # Add the errandee's interest to the database with the status 'requested'
        db.execute("INSERT INTO interested_errands (errand_id, errandee_id, status) VALUES (?, ?, 'requested')", errand_id, session["user_id"])

        # Update the errander's notification count
        errander_id = db.execute("SELECT user_id FROM errands WHERE id = ?", errand_id)[0]['user_id']
        db.execute("UPDATE users SET interested_count = interested_count + 1 WHERE id = ?", errander_id)

        flash(f"You have expressed interest in this errand.")
    else:
        flash(f"You have already expressed interest in this errand.")

    return redirect(url_for("errandee_dashboard"))


@app.route("/notification")
@login_required
def notification():
    # Fetch interested errandees for the errands posted by the errander
    errander_id = session["user_id"]
    interested_errandees = db.execute("""
        SELECT u.fullname, u.profile_picture, u.country, u.whatsappnumber, u.phonenumber, u.errands_done, ie.errand_id, ie.request_status, u.id AS id
        FROM interested_errands ie
        JOIN users u ON u.id = ie.errandee_id
        JOIN errands e ON e.id = ie.errand_id
        WHERE e.user_id = ? AND e.status = 'open'
    """, errander_id)

    # Update interested count by excluding completed errands
    interested_count = db.execute("""
        SELECT COUNT(*)
        FROM interested_errands ie
        JOIN errands e ON e.id = ie.errand_id
        WHERE e.user_id = ? AND e.status = 'open'
    """, errander_id)[0]["COUNT(*)"]

    # Calculate the number of interested errandees
    interested_count = len(interested_errandees)

    # Reset the interested count after fetching
    db.execute("UPDATE users SET interested_count = 0 WHERE id = ?", errander_id)

    return render_template("notification.html", errandees=interested_errandees, interested_count=interested_count)


@app.route("/done_errand/<int:errand_id>/<int:errandee_id>")
@login_required
def done_errand(errand_id, errandee_id):
    #errand_id = request.form.get("errand_id")  # Get the errand ID from the form

    # Increment errands done count in the database
    db.execute("UPDATE users SET errands_done = errands_done + 1 WHERE id = ?", errandee_id)

    # Mark the errand as done in the `interested_errands` table
    db.execute("""
        UPDATE interested_errands
        SET request_status = 'done'
        WHERE errand_id = ? AND errandee_id = ?
    """, errand_id, errandee_id)

    # Mark the errand as completed
    #db.execute("""
        #UPDATE errands
        #SET status = 'completed'
        #WHERE id = ?
    #""", errand_id)

    # # Optionally: Clear the interested errandees
    # db.execute("""
    #     DELETE FROM interested_errands
    #     WHERE errand_id = ?
    # """, errand_id)
    
    flash(f"Errand marked as done!")
    return redirect(url_for("notification"))  # Redirect back to the notification page


@app.route("/requested_errands")
@login_required
def request_errands():
    errandee_id = session["user_id"]
    requested_errands = db.execute("""
        SELECT e.description, e.location, e.status AS errand_status, ie.request_status AS interest_status,
                u.fullname, u.country, u.profile_picture
        FROM interested_errands ie
        JOIN errands e ON e.id = ie.errand_id
        JOIN users u ON u.id = e.user_id
        WHERE ie.errandee_id = ? AND e.status = 'open'
    """, errandee_id)

    return render_template("requested_errand.html", requested_errands=requested_errands)


@app.route("/accept_errandee/<int:errand_id>/<int:errandee_id>")
@login_required
def accept_errandee(errand_id, errandee_id):
    # Set the selected errandee's status to 'accepted' for the specified errand
    db.execute("UPDATE interested_errands SET request_status = 'accepted' WHERE errand_id = ? AND errandee_id = ?", errand_id, errandee_id)
    
    # Set the status of other errandees who expressed interest in the same errand to 'not accepted'
    db.execute("UPDATE interested_errands SET request_status = 'not accepted' WHERE errand_id = ? AND errandee_id != ?", errand_id, errandee_id)

    # Create a notification for the accepted errandee
    db.execute("""
        INSERT INTO notifications (errand_id, errandee_id, message)
        VALUES (?, ?, ?)
    """, errand_id, errandee_id, "You have been accepted for an errand!")
    
    flash("Errandee has been sent on Errand")
    return redirect(url_for("notification"))


@app.route("/errand_not_done/<int:errand_id>/<int:errandee_id>", methods=["GET", "POST"])
@login_required
def errand_not_done(errand_id, errandee_id):
    user_id = session["user_id"]
    interested_count = get_interested_count(user_id)
    if request.method == "POST":
        # Get the reason from the form
        reason = request.form.get("reason")
        
        # Insert the reason into the errand_not_done table
        db.execute("""
            INSERT INTO errand_not_done (errand_id, errandee_id, reason)
            VALUES (?, ?, ?)
        """, errand_id, errandee_id, reason)
        
        # Remove the errandee's interest from `interested_errands`
        db.execute("""
            DELETE FROM interested_errands
            WHERE errand_id = ? AND errandee_id = ?
        """, errand_id, errandee_id)

        flash("Reason for 'Errand Not Done' has been recorded.")
        return redirect(url_for("notification"))

    return render_template("errand_not_done.html", errand_id=errand_id, errandee_id=errandee_id, interested_count=interested_count)


@app.route("/mark_notifications_read")
@login_required
def mark_notifications_read():
    user_id = session["user_id"]
    db.execute("UPDATE notifications SET status = 'read' WHERE errandee_id = ?", user_id)
    return redirect(url_for("errandee_dashboard"))


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/") 

    
if __name__ == '__main__':
    app.run(debug=True)
