import sqlite3

conn = sqlite3.connect("users.db")  # Відкриваємо базу
cursor = conn.cursor()

cursor.execute("SELECT * FROM users")  # Отримуємо всі записи
users = cursor.fetchall()

if users:
    for user in users:
        print(user)
else:
    print("База даних порожня!")

conn.close()
