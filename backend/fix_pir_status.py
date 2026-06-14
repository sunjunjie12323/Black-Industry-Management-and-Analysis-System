import sqlite3
conn = sqlite3.connect('threat_intel.db')
cursor = conn.cursor()
cursor.execute("UPDATE pir SET status='active' WHERE status='executing'")
print(f'Updated {cursor.rowcount} PIRs from executing to active')
conn.commit()
cursor.execute('SELECT id, title, status, priority FROM pir')
for row in cursor.fetchall():
    print(f'  {row[1]}: status={row[2]}, priority={row[3]}')
conn.close()
