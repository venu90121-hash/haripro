import streamlit as st
import sqlite3
import hashlib
from datetime import datetime, timedelta
import json
import os

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('hobbies.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)')
    c.execute('''CREATE TABLE IF NOT EXISTS hobbies 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, category TEXT, 
                  target_days INTEGER, goal TEXT, practice_dates TEXT, user_id INTEGER)''')
    conn.commit()
    conn.close()

init_db()

# --- HELPER FUNCTIONS ---
def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_password(password, hashed):
    return hash_password(password) == hashed

# --- UI LOGIC ---
st.set_page_config(page_title="Hobby Tracker", layout="wide")

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

# --- LOGIN / REGISTER UI ---
if not st.session_state['logged_in']:
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab2:
        new_user = st.text_input("New Username")
        new_pass = st.text_input("New Password", type="password")
        if st.button("Register"):
            conn = sqlite3.connect('hobbies.db')
            c = conn.cursor()
            try:
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (new_user, hash_password(new_pass)))
                conn.commit()
                st.success("Account created! Please login.")
            except:
                st.error("Username already exists.")
            conn.close()

    with tab1:
        user = st.text_input("Username")
        pas = st.text_input("Password", type="password")
        if st.button("Login"):
            conn = sqlite3.connect('hobbies.db')
            c = conn.cursor()
            res = c.execute('SELECT id, password FROM users WHERE username = ?', (user,)).fetchone()
            if res and check_password(pas, res[1]):
                st.session_state['logged_in'] = True
                st.session_state['user_id'] = res[0]
                st.session_state['username'] = user
                st.rerun()
            else:
                st.error("Invalid credentials")

# --- MAIN APP UI ---
else:
    st.sidebar.title(f"Welcome, {st.session_state['username']}")
    if st.sidebar.button("Logout"):
        st.session_state['logged_in'] = False
        st.rerun()

    menu = ["Dashboard", "Add Hobby", "Challenges"]
    choice = st.sidebar.selectbox("Navigation", menu)

    if choice == "Dashboard":
        st.header("Your Hobbies")
        conn = sqlite3.connect('hobbies.db')
        hobbies = conn.execute('SELECT * FROM hobbies WHERE user_id = ?', (st.session_state['user_id'],)).fetchall()
        
        for h in hobbies:
            with st.expander(f"{h[1]} ({h[2]})"):
                st.write(f"Goal: {h[4]}")
                if st.button(f"Mark Practice for {h[1]}", key=h[0]):
                    # Update database logic here
                    st.success("Done!")
        conn.close()

    elif choice == "Add Hobby":
        st.header("Add New Hobby")
        with st.form("add_form"):
            name = st.text_input("Hobby Name")
            cat = st.selectbox("Category", ["Sport", "Art", "Learning", "Health"])
            target = st.number_input("Target Days per Week", 1, 7)
            if st.form_submit_button("Save"):
                conn = sqlite3.connect('hobbies.db')
                conn.execute('INSERT INTO hobbies (name, category, target_days, user_id) VALUES (?,?,?,?)', 
                             (name, cat, target, st.session_state['user_id']))
                conn.commit()
                st.success("Hobby Added!")
