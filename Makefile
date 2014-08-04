all: deps
	urweb -dbms sqlite -db ./test.db example
db:
	sqlite3 test.db < test.sql
deps:
	gcc -c -I/usr/local/include/urweb ./ur-pbkdf2/pbkdf2.c -o ./ur-pbkdf2/pbkdf2.o
