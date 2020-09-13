#include <stdio.h>
#include <string.h>
#include "llist.h"

void * search(void *ctx, void *data);

int
main()
{
	char *str1 = "str1";
	char *str2 = "str2";
	char *str3 = "str3";
	char *str4 = "str4";
	char *str_found;
	struct llist *msgs;
	int found;

	msgs = llist_init((void *)str1);
	llist_append(msgs, (void *)str2);
	llist_append(msgs, (void *)str3);

	found = llist_search(msgs, (void *)str1, search, (void *)&str_found);
	printf("Searched for: %s, found: %s (%d)\n", str1, str_found, found);
	found = llist_search(msgs, (void *)str2, search, (void *)&str_found);
	printf("Searched for: %s, found: %s (%d)\n", str2, str_found, found);
	found = llist_search(msgs, (void *)str3, search, (void *)&str_found);
	printf("Searched for: %s, found: %s (%d)\n", str3, str_found, found);
	found = llist_search(msgs, (void *)str4, search, (void *)&str_found);
	printf("Searched for: %s, found: %s (%d)\n", str4, str_found, found);
	
	llist_destroy(msgs, NULL, NULL);

	return 0;
}

void *
search(void *str, void *data)
{
	return (void *)(!strcmp((char *)str, (char *)data));
}
