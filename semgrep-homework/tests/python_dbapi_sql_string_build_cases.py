import sqlite3


def bad_percent(cur, username):
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cur.execute(query)


def bad_fstring(cur, email):
    query = f"SELECT * FROM users WHERE email = '{email}'"
    cur.execute(query)


def bad_format(cur, username, pw_hash, email):
    query = "INSERT INTO users (username, pw_hash, email) VALUES ('{}', '{}', '{}')".format(
        username, pw_hash, email
    )
    cur.execute(query)


def ok_parameterized_select(cur, username):
    query = "SELECT * FROM users WHERE username = ?"
    cur.execute(query, (username,))


def ok_parameterized_insert(cur, username, pw_hash, email):
    cur.execute(
        "INSERT INTO users (username, pw_hash, email) VALUES (?, ?, ?)",
        (username, pw_hash, email),
    )


def ok_constant_query(cur):
    query = "SELECT * FROM users"
    cur.execute(query)
