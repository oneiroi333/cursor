.PHONY: clean

cursor: src/cursor.c src/binload.c src/llist.c src/queue.c
	gcc -I./include src/binload.c src/llist.c src/queue.c -lbfd -lcapstone $< -o $@

clean:
	rm -fv cursor
