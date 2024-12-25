from flask import Flask, render_template, request
import hashlib
import re

app = Flask(__name__, template_folder='templates', static_folder='static')

# Sample algorithm security levels for comparison
algorithm_security = {
    "MD5": 1,
    "SHA-1": 2,
    "SHA-256": 5,
    "SHA-512": 5,
}

@app.route('/')
def loading_page():
    return render_template('index.html')

@app.route('/welcome')
def welcome_page():
    return render_template('welcome.html')

@app.route('/generate-hash', methods=['GET', 'POST'])
def generate_hash():
    hash_result = None
    if request.method == 'POST':
        algorithm = request.form.get('algorithm')
        text = request.form.get('text', '')
        file = request.files.get('file')
        if text:
            if algorithm == 'md5':
                hash_result = hashlib.md5(text.encode()).hexdigest()
            elif algorithm == 'sha1':
                hash_result = hashlib.sha1(text.encode()).hexdigest()
            elif algorithm == 'sha256':
                hash_result = hashlib.sha256(text.encode()).hexdigest()
            elif algorithm == 'sha512':
                hash_result = hashlib.sha512(text.encode()).hexdigest()
        elif file:
            file_content = file.read()
            if algorithm == 'md5':
                hash_result = hashlib.md5(file_content).hexdigest()
            elif algorithm == 'sha1':
                hash_result = hashlib.sha1(file_content).hexdigest()
            elif algorithm == 'sha256':
                hash_result = hashlib.sha256(file_content).hexdigest()
            elif algorithm == 'sha512':
                hash_result = hashlib.sha512(file_content).hexdigest()
    return render_template('generate-hash.html', hash_result=hash_result)

@app.route('/compare-hashes', methods=['GET', 'POST'])
def compare_hashes():
    result = None
    if request.method == 'POST':
        hash1 = request.form.get('hash1')
        hash2 = request.form.get('hash2')
        result = "Match" if hash1 == hash2 else "Do not match"
    return render_template('compare-hashes.html', result=result)

@app.route('/compare-algorithms', methods=['GET', 'POST'])
def compare_algorithms():
    comparison_result = ""
    if request.method == 'POST':
        algorithm1 = request.form['algorithm1']
        algorithm2 = request.form['algorithm2']
        sec1 = algorithm_security.get(algorithm1, 0)
        sec2 = algorithm_security.get(algorithm2, 0)
        if algorithm1 == algorithm2:
            comparison_result = f"The selected algorithms are same."
            #comparison_result = f"{algorithm1} and {algorithm2} are equally secure."
        elif sec1 > sec2:
            comparison_result = f"{algorithm1} is more secure than {algorithm2}."
        elif sec1 < sec2:
            comparison_result = f"{algorithm2} is more secure than {algorithm1}."
        else:
            comparison_result = f"The selected algorithms are same."
            #comparison_result = f"{algorithm1} and {algorithm2} are equally secure."
    return render_template('compare-algorithms.html', comparison_result=comparison_result)

@app.route('/salted-hash', methods=['GET', 'POST'])
def salted_hash():
    salted_hash = None
    if request.method == 'POST':
        text = request.form.get('text', '')  # Get text input
        salt = request.form.get('salt', '')  # Get custom salt
        file = request.files.get('file')  # Get uploaded file
        algorithm = request.form.get('algorithm', '')

        # If no salt is provided, generate a random one
        if not salt:
            import os
            salt = os.urandom(16).hex()

        # Read file content if a file is uploaded
        file_content = ''
        if file and file.filename:
            try:
                file_content = file.read().decode('utf-8')  # Decode file content to string
            except Exception as e:
                file_content = ''
                print(f"Error reading file: {e}")

        # Combine text and file content
        combined_input = text + file_content + salt

        # Hash the combined input based on the selected algorithm
        if algorithm == 'md5':
            salted_hash = hashlib.md5(combined_input.encode()).hexdigest()
        elif algorithm == 'sha1':
            salted_hash = hashlib.sha1(combined_input.encode()).hexdigest()
        elif algorithm == 'sha256':
            salted_hash = hashlib.sha256(combined_input.encode()).hexdigest()
        elif algorithm == 'sha512':
            salted_hash = hashlib.sha512(combined_input.encode()).hexdigest()

    return render_template('salted-hash.html', salted_hash=salted_hash)

@app.route('/password-checker', methods=['GET', 'POST'])
def password_checker():
    password_strength = None
    if request.method == 'POST':
        password = request.form.get('password')
        if len(password) < 8:
            password_strength = "Weak: Password must be at least 8 characters."
        elif not re.search(r"[A-Z]", password):
            password_strength = "Weak: Password must contain at least one uppercase letter."
        elif not re.search(r"[a-z]", password):
            password_strength = "Weak: Password must contain at least one lowercase letter."
        elif not re.search(r"\d", password):
            password_strength = "Weak: Password must contain at least one digit."
        elif not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            password_strength = "Moderate: Adding special characters can make it stronger."
        else:
            password_strength = "Strong Password!"
    return render_template('password-checker.html', password_strength=password_strength)

@app.route('/toggle-theme', methods=['GET', 'POST'])
def toggle_theme():
    return render_template('toggle-theme.html')

if __name__ == '__main__':
    app.run(debug=True) 