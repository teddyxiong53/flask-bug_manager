from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import hashlib
import os
from datetime import datetime
import pandas as pd

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a secure key in production

# Database initialization
def init_database():
    conn = sqlite3.connect('bug_manager.db')
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Create bugs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS bugs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        priority TEXT NOT NULL,
        expected_fix_date TEXT NOT NULL,
        status TEXT NOT NULL,
        assignee TEXT NOT NULL,
        notes TEXT,
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Add default admin account if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        password_hash = hashlib.sha256('admin'.encode()).hexdigest()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', password_hash))

    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('bug_manager.db')
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Initialize database if not exists
if not os.path.exists('bug_manager.db'):
    init_database()

# Routes
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and user['password'] == hash_password(password):
            session['user'] = {'id': user['id'], 'username': user['username']}
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_confirm = request.form['password_confirm']

        if password != password_confirm:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        if cursor.fetchone()[0] > 0:
            conn.close()
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hash_password(password))
        )
        conn.commit()
        conn.close()

        flash('Registration successful, please login', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/add_bug', methods=['GET', 'POST'])
def add_bug():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        data = {
            'title': request.form['title'],
            'description': request.form['description'],
            'priority': request.form['priority'],
            'expected_fix_date': request.form['expected_fix_date'],
            'status': request.form['status'],
            'assignee': request.form['assignee'],
            'notes': request.form.get('notes', '')
        }

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO bugs (title, description, priority, expected_fix_date, status, assignee, notes, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['title'], data['description'], data['priority'], data['expected_fix_date'],
            data['status'], data['assignee'], data['notes'], session['user']['username']
        ))
        conn.commit()
        conn.close()

        flash('Bug added successfully', 'success')
        return redirect(url_for('bug_list'))

    return render_template('add_bug.html')

@app.route('/bug_list')
def bug_list():
    if 'user' not in session:
        return redirect(url_for('login'))

    priority_filter = request.args.get('priority', 'all')
    status_filter = request.args.get('status', 'all')

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM bugs"
    params = []
    conditions = []

    if priority_filter != 'all':
        conditions.append("priority = ?")
        params.append(priority_filter)

    if status_filter != 'all':
        conditions.append("status = ?")
        params.append(status_filter)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY created_at DESC"

    cursor.execute(query, params)
    bugs = cursor.fetchall()
    conn.close()

    return render_template('bug_list.html', bugs=bugs)

@app.route('/bug/<int:bug_id>')
def view_bug(bug_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM bugs WHERE id = ?", (bug_id,))
    bug = cursor.fetchone()
    conn.close()

    if not bug:
        flash('Bug not found', 'error')
        return redirect(url_for('bug_list'))

    return render_template('view_bug.html', bug=bug)

@app.route('/edit_bug/<int:bug_id>', methods=['GET', 'POST'])
def edit_bug(bug_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM bugs WHERE id = ?", (bug_id,))
    bug = cursor.fetchone()

    if not bug:
        conn.close()
        flash('Bug not found', 'error')
        return redirect(url_for('bug_list'))

    if request.method == 'POST':
        data = {
            'title': request.form['title'],
            'description': request.form['description'],
            'priority': request.form['priority'],
            'expected_fix_date': request.form['expected_fix_date'],
            'status': request.form['status'],
            'assignee': request.form['assignee'],
            'notes': request.form.get('notes', '')
        }

        cursor.execute('''
        UPDATE bugs
        SET title = ?, description = ?, priority = ?, expected_fix_date = ?,
            status = ?, assignee = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        ''', (
            data['title'], data['description'], data['priority'], data['expected_fix_date'],
            data['status'], data['assignee'], data['notes'], bug_id
        ))
        conn.commit()
        conn.close()

        flash('Bug updated successfully', 'success')
        return redirect(url_for('bug_list'))

    conn.close()
    return render_template('edit_bug.html', bug=bug)

@app.route('/delete_bug/<int:bug_id>', methods=['POST'])
def delete_bug(bug_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT title FROM bugs WHERE id = ?", (bug_id,))
    bug = cursor.fetchone()

    if not bug:
        conn.close()
        flash('Bug not found', 'error')
        return redirect(url_for('bug_list'))

    cursor.execute("DELETE FROM bugs WHERE id = ?", (bug_id,))
    conn.commit()
    conn.close()

    flash('Bug deleted successfully', 'info')
    return redirect(url_for('bug_list'))

@app.route('/statistics')
def statistics():
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM bugs")
    bugs = cursor.fetchall()
    conn.close()

    if not bugs:
        return render_template('statistics.html', no_data=True)

    # Define column names explicitly to match the bugs table schema
    columns = ['id', 'title', 'description', 'priority', 'expected_fix_date', 'status',
               'assignee', 'notes', 'created_by', 'created_at', 'updated_at']
    # Convert sqlite3.Row objects to dictionaries
    bugs_data = [dict(zip(columns, bug)) for bug in bugs]

    # Create DataFrame with explicit columns
    df = pd.DataFrame(bugs_data, columns=columns)

    priority_counts = df.groupby('priority').size().reset_index(name='count')
    status_counts = df.groupby('status').size().reset_index(name='count')
    assignee_counts = df.groupby('assignee').size().reset_index(name='count')
    creator_counts = df.groupby('created_by').size().reset_index(name='count')
    high_priority = df[(df['priority'].isin(['高', '紧急'])) & (df['status'].isin(['待处理', '处理中']))]

    return render_template(
        'statistics.html',
        priority_counts=priority_counts.to_dict('records'),
        status_counts=status_counts.to_dict('records'),
        assignee_counts=assignee_counts.to_dict('records'),
        creator_counts=creator_counts.to_dict('records'),
        high_priority=high_priority.to_dict('records')
    )

if __name__ == '__main__':
    app.run(debug=True, port=8081, host='0.0.0.0')