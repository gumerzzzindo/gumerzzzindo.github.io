# Dorks : Para Script Kiddies

Hacer Dorking es una tarea de OSINT que sirve para buscar información de fuentes abiertas indexada. Normalmente se suele usar Google para este tipo de tareas.

## Ejemplos de Dork:

Exploit-DB tiene un apartado exclusivamente de Dorks (https://www.exploit-db.com/google-hacking-database).

### SQL-I


inurl:index.php?id=
inurl:.asp?id=
"You have an error in your SQL syntax"
intext:"select * from"
inurl:login.php
inurl:admin/login.php
"Warning: mysql_fetch_array() expects parameter 1"
inurl:".php?cat="
filetype:sql "sql backup"
"ORA-00933: SQL command not properly ended"
inurl:product.php?id=
inurl:page.php?id=
inurl:view.php?id=
inurl:.php?id= intext:"mysql"
inurl:search.php?q=
filetype:sql inurl:dump
filetype:env "DB_PASSWORD"
inurl:wp-content/plugins/
filetype:sql "backup"
"phpMyAdmin" "error" "db"
