from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import sqlite3
import json
import os
from reports import generate_weekly_report, generate_monthly_report

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database setup
def init_db():
    conn = sqlite3.connect('hobbies.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS hobbies
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  category TEXT,
                  target_days INTEGER,
                  goal TEXT,
                  practice_dates TEXT,
                  user_id INTEGER,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS challenges
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  description TEXT,
                  hobby_category TEXT,
                  start_date TEXT,
                  end_date TEXT,
                  target_value INTEGER,
                  points INTEGER,
                  creator_id INTEGER,
                  is_global BOOLEAN,
                  FOREIGN KEY (creator_id) REFERENCES users (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS challenge_participants
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  challenge_id INTEGER,
                  user_id INTEGER,
                  current_progress INTEGER DEFAULT 0,
                  points_earned INTEGER DEFAULT 0,
                  join_date TEXT,
                  FOREIGN KEY (challenge_id) REFERENCES challenges (id),
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    conn.commit()
    conn.close()

init_db()

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @staticmethod
    def get(user_id):
        conn = sqlite3.connect('hobbies.db')
        c = conn.cursor()
        user = c.execute('SELECT id, username FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        return User(user[0], user[1]) if user else None

@login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

def get_db():
    conn = sqlite3.connect('hobbies.db')
    conn.row_factory = sqlite3.Row
    return conn

def calculate_streak(dates):
    if not dates:
        return 0
    dates = sorted([datetime.strptime(d, "%Y-%m-%d %H:%M:%S.%f") for d in dates])
    current_streak = 1
    last_date = dates[-1]
    
    for i in range(len(dates)-2, -1, -1):
        if (dates[i] + timedelta(days=1)).date() == dates[i+1].date():
            current_streak += 1
        else:
            break
    
    if datetime.now() - last_date > timedelta(days=1):
        current_streak = 0
        
    return current_streak

def get_reminders(user_id):
    conn = get_db()
    c = conn.cursor()
    hobbies = c.execute('SELECT * FROM hobbies WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    
    reminders = []
    today = datetime.now().date()
    
    for hobby in hobbies:
        practice_dates = json.loads(hobby['practice_dates'] or '[]')
        if not practice_dates:
            last_practice = None
        else:
            last_practice = datetime.strptime(practice_dates[-1], "%Y-%m-%d %H:%M:%S.%f").date()
        
        target_days = hobby['target_days']
        days_per_week = 7
        
        # Calculate days since last practice
        if last_practice is None:
            days_since_practice = None
            status = 'never'
        else:
            days_since_practice = (today - last_practice).days
            if days_since_practice == 0:
                status = 'done'
            else:
                # Calculate if we're behind schedule
                expected_days_between_practice = days_per_week / target_days
                if days_since_practice > expected_days_between_practice:
                    status = 'overdue'
                else:
                    status = 'on_track'
        
        reminder = {
            'hobby_name': hobby['name'],
            'target_days': target_days,
            'last_practice': last_practice,
            'days_since_practice': days_since_practice,
            'status': status
        }
        reminders.append(reminder)
    
    return reminders

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        c = conn.cursor()
        
        if c.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            conn.close()
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                 (username, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        c = conn.cursor()
        user = c.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user['password'], password):
            login_user(User(user['id'], user['username']))
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    conn = get_db()
    c = conn.cursor()
    hobbies = c.execute('SELECT * FROM hobbies WHERE user_id = ?', (current_user.id,)).fetchall()
    conn.close()
    
    hobby_list = []
    for hobby in hobbies:
        practice_dates = json.loads(hobby['practice_dates'] or '[]')
        streak = calculate_streak(practice_dates)
        level = len(practice_dates) // 5
        practices_for_level = len(practice_dates) % 5
        progress = (practices_for_level / 5) * 100
        
        hobby_dict = dict(hobby)
        hobby_dict.update({
            'streak': streak,
            'level': level,
            'progress': progress
        })
        hobby_list.append(hobby_dict)
    
    reminders = get_reminders(current_user.id)
    return render_template('index.html', hobbies=hobby_list, reminders=reminders)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_hobby():
    if request.method == 'POST':
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO hobbies 
                     (name, category, target_days, goal, practice_dates, user_id)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 (request.form['name'],
                  request.form['category'],
                  int(request.form['target_days']),
                  request.form['goal'],
                  '[]',
                  current_user.id))
        conn.commit()
        conn.close()
        
        flash(f'New hobby "{request.form["name"]}" added successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('add.html')

@app.route('/practice/<int:id>', methods=['POST'])
@login_required
def practice_hobby(id):
    conn = get_db()
    c = conn.cursor()
    hobby = c.execute('SELECT * FROM hobbies WHERE id = ? AND user_id = ?',
                     (id, current_user.id)).fetchone()
    
    if hobby:
        practice_dates = json.loads(hobby['practice_dates'] or '[]')
        practice_dates.append(str(datetime.now()))
        
        c.execute('UPDATE hobbies SET practice_dates = ? WHERE id = ?',
                 (json.dumps(practice_dates), id))
        conn.commit()
        flash(f'Great job! You practiced {hobby["name"]}!', 'success')
    else:
        flash('Hobby not found or unauthorized access!', 'danger')
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_hobby(id):
    conn = get_db()
    c = conn.cursor()
    hobby = c.execute('SELECT * FROM hobbies WHERE id = ? AND user_id = ?',
                     (id, current_user.id)).fetchone()
    
    if hobby:
        c.execute('DELETE FROM hobbies WHERE id = ?', (id,))
        conn.commit()
        flash(f'Hobby "{hobby["name"]}" has been deleted.', 'success')
    else:
        flash('Hobby not found or unauthorized access!', 'danger')
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/reports/<type>')
@login_required
def reports(type):
    if type not in ['weekly', 'monthly']:
        return redirect(url_for('reports', type='weekly'))
    
    if type == 'weekly':
        report_data = generate_weekly_report(current_user.id)
    else:
        report_data = generate_monthly_report(current_user.id)
    
    return render_template('reports.html', report=report_data, report_type=type)

@app.route('/challenges')
@login_required
def challenges():
    conn = get_db()
    c = conn.cursor()
    
    # Get global challenges
    global_challenges = c.execute('''
        SELECT c.*, u.username as creator_name,
        (SELECT COUNT(*) FROM challenge_participants WHERE challenge_id = c.id) as participant_count
        FROM challenges c
        JOIN users u ON c.creator_id = u.id
        WHERE c.is_global = 1 AND c.end_date > ?
    ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),)).fetchall()
    
    # Get user's participated challenges
    my_challenges = c.execute('''
        SELECT c.*, cp.current_progress, cp.points_earned
        FROM challenges c
        JOIN challenge_participants cp ON c.id = cp.challenge_id
        WHERE cp.user_id = ?
    ''', (current_user.id,)).fetchall()
    
    conn.close()
    
    return render_template('challenges.html', 
                         global_challenges=global_challenges,
                         my_challenges=my_challenges)

@app.route('/create_challenge', methods=['GET', 'POST'])
@login_required
def create_challenge():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        hobby_category = request.form['hobby_category']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        target_value = int(request.form['target_value'])
        points = int(request.form['points'])
        is_global = 'is_global' in request.form
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO challenges 
                    (title, description, hobby_category, start_date, end_date,
                     target_value, points, creator_id, is_global)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (title, description, hobby_category, start_date, end_date,
                  target_value, points, current_user.id, is_global))
        
        # Auto-join creator to their own challenge
        challenge_id = c.lastrowid
        c.execute('''INSERT INTO challenge_participants
                    (challenge_id, user_id, join_date)
                    VALUES (?, ?, ?)''',
                 (challenge_id, current_user.id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        
        conn.commit()
        conn.close()
        flash('Challenge created successfully!', 'success')
        return redirect(url_for('challenges'))
        
    return render_template('create_challenge.html')

@app.route('/join_challenge/<int:challenge_id>')
@login_required
def join_challenge(challenge_id):
    conn = get_db()
    c = conn.cursor()
    
    # Check if already joined
    existing = c.execute('''SELECT 1 FROM challenge_participants 
                           WHERE challenge_id = ? AND user_id = ?''',
                        (challenge_id, current_user.id)).fetchone()
    
    if not existing:
        c.execute('''INSERT INTO challenge_participants
                    (challenge_id, user_id, join_date)
                    VALUES (?, ?, ?)''',
                 (challenge_id, current_user.id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        flash('Successfully joined the challenge!', 'success')
    else:
        flash('You are already participating in this challenge!', 'info')
    
    conn.close()
    return redirect(url_for('challenges'))

@app.route('/update_challenge_progress/<int:challenge_id>', methods=['POST'])
@login_required
def update_challenge_progress(challenge_id):
    progress = int(request.form['progress'])
    
    conn = get_db()
    c = conn.cursor()
    
    # Get challenge details
    challenge = c.execute('SELECT * FROM challenges WHERE id = ?', (challenge_id,)).fetchone()
    
    # Update progress
    c.execute('''UPDATE challenge_participants 
                 SET current_progress = ?,
                     points_earned = CASE 
                         WHEN ? >= target_value THEN points
                         ELSE (points * ? / target_value)
                     END
                 WHERE challenge_id = ? AND user_id = ?''',
              (progress, progress, progress, challenge_id, current_user.id))
    
    conn.commit()
    conn.close()
    
    flash('Progress updated successfully!', 'success')
    return redirect(url_for('challenges'))

@app.route('/leaderboard')
@login_required
def leaderboard():
    conn = get_db()
    c = conn.cursor()
    
    # Get top participants across all challenges
    leaderboard_data = c.execute('''
        SELECT u.username,
               SUM(cp.points_earned) as total_points,
               COUNT(DISTINCT cp.challenge_id) as challenges_participated
        FROM users u
        JOIN challenge_participants cp ON u.id = cp.user_id
        GROUP BY u.id
        ORDER BY total_points DESC
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    return render_template('leaderboard.html', leaderboard_data=leaderboard_data)

if __name__ == '__main__':
    app.run(debug=True)
