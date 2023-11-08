from flask import Flask, request, render_template
import re
import requests

app = Flask(__name__)

@app.after_request
def add_no_cache_headers(response):
    response.cache_control.no_cache = True
    response.cache_control.no_store = True
    response.cache_control.must_revalidate = True
    response.cache_control.max_age = 0
    return response

def check_xss_vulnerability(user_input):
    xss_patterns = [
        r'<\s*script[^>]*>',    
        r'\bon\w+\s*=',          
        r'javascript:',          
        r'data:',                 
    ]
    for pattern in xss_patterns:
        if re.search(pattern, user_input, re.I):
            return True
    return False

def check_sql_injection_vulnerability(user_input):
    try:
        payloads = [
            "1' OR '1' = '1",
            "1' OR '1' = '1' --",
            "1' OR '1' = '1' #",
        ]

        for payload in payloads:
            test_url = f"http://your-website.com/your-endpoint?user_input={payload}"
            response = requests.get(test_url)

            if "error" in response.text.lower() or "exception" in response.text.lower():
                return True

        return False
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/', methods=['GET', 'POST'])
def index():
    xss_result = None
    sql_injection_result = None
    prevention_info = {}

    if request.method == 'POST':
        user_input = request.form['user_input']
        xss_result = check_xss_vulnerability(user_input)
        sql_injection_result = check_sql_injection_vulnerability(user_input)

        if xss_result:
            prevention_info['xss'] = "To prevent XSS, sanitize user input and use output encoding."

        if sql_injection_result:
            prevention_info['sql_injection'] = "To prevent SQL Injection, use parameterized queries or prepared statements."

    return render_template('index.html', xss_result=xss_result, sql_injection_result=sql_injection_result, prevention_info=prevention_info)

if __name__ == '__main__':
    app.run(debug=True)
