import csv
import bcrypt
import requests
import re


CSV_FILE = 'regno.csv'
API_KEY = 'ad7c057e691a40528e319a2752d2c0af'  
MAX_ATTEMPTS = 5


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_valid_password(password):
    return len(password) >= 8 and re.search(r"[@$!%*?&]", password)

def read_user_data():
    try:
        with open(CSV_FILE, mode='r') as file:
            reader = csv.DictReader(file)
            return list(reader)
    except FileNotFoundError:
        return []

def save_user_data(data):
    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['email', 'password', 'security_question'])
        writer.writeheader()
        writer.writerows(data)

def get_user(email):
    users = read_user_data()
    for user in users:
        if user['email'] == email:
            return user
    return None

def register_user():
    email = input("Enter your email for registration: ").strip()
    
    if not is_valid_email(email):
        print("Invalid email format.")
        return

    if get_user(email):
        print("This email is already registered.")
        return

    password = input("Enter your password (min 8 characters, 1 special character): ").strip()
    
    if not is_valid_password(password):
        print("Password must be at least 8 characters long and contain one special character.")
        return

    hashed_password = hash_password(password).decode('utf-8')
    
    security_question = input("Enter a security question (for password recovery): ").strip()

    new_user = {
        'email': email,
        'password': hashed_password,
        'security_question': security_question
    }

    users = read_user_data()
    users.append(new_user)
    save_user_data(users)
    print("Registration successful! You can now log in.")


def login():
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        email = input("Enter your email: ").strip()
        if not is_valid_email(email):
            print("Invalid email format.")
            continue

        password = input("Enter your password: ").strip()
        user = get_user(email)

        if user and check_password(user['password'].encode('utf-8'), password):
            print("Login successful!")
            fetch_news_headlines()
            return
        else:
            print("Invalid email or password.")
            attempts += 1

    print("Too many failed login attempts. Please try again later.")

def forgot_password():
    email = input("Enter your registered email: ").strip()
    user = get_user(email)

    if not user:
        print("Email not found.")
        return

    answer = input(f"{user['security_question']}: ").strip()
    if answer.lower() == 'your_answer_here':  # Replace with actual answer for testing
        new_password = input("Enter new password: ").strip()
        if not is_valid_password(new_password):
            print("Password must be at least 8 characters long and contain one special character.")
            return

        hashed = hash_password(new_password)
        user['password'] = hashed.decode('utf-8')

        users = read_user_data()
        for u in users:
            if u['email'] == email:
                u['password'] = user['password']
        save_user_data(users)
        print("Password reset successfully!")
    else:
        print("Incorrect answer.")

def fetch_news_headlines():
    while True:
        keyword = input("\nEnter a keyword for news (or type 'exit' to return to the main menu): ").strip()

        if keyword.lower() == 'exit':
            print("Returning to main menu...\n")
            break

        url = f'https://newsapi.org/v2/everything?q={keyword}&apiKey={API_KEY}'

        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                if data['totalResults'] == 0:
                    print("No news found for this keyword.")
                else:
                    headlines = data['articles'][:5]
                    print("\nTop 5 headlines:")
                    for idx, article in enumerate(headlines, 1):
                        print(f"{idx}. {article['title']} (Source: {article['source']['name']})")
            elif response.status_code == 401:
                print("Invalid API key. Please check your API key.")
            else:
                print(f"Error: {response.status_code}")
        except requests.exceptions.RequestException:
            print("Network error. Please check your internet connection.")

def main():
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Forgot Password")
        print("4. Exit")
        choice = input("Choose an option: ").strip()

        if choice == '1':
            register_user()
        elif choice == '2':
            login()
        elif choice == '3':
            forgot_password()
        elif choice == '4':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
