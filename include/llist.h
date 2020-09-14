#ifndef __LLIST__
#define __LLIST__

enum llist_error {
	LLIST_ENOMEM
};

/*
 * Functions that operate on node data
 * @params:
 * 	context: function context
 *	data: node data
 * @returns:
 *	generic return value
 */
typedef void *(*llist_data_func_t)(void *context, void *data);

struct llist {
	void *data;
	struct llist *next;
};

/*
 * Create a new linked list
 *
 * @params:
 * 	data: pointer to data for the first node
 * @returns:
 * 	pointer to llist struct
 */
struct llist *llist_init(void *data);

/*
 * Destroy a linked list
 *
 * @params:
 * 	llist: linked list to destroy
 *  data_func_ctx: context information for data_dtor
 * 	data_dtor: Data destructor function which gets called for every llist node
 * @returns;
 * 	-
 */
void llist_destroy(struct llist *llist, void *data_func_ctx, llist_data_func_t data_dtor);

/*
 * Append a new node to a linked list
 *
 * @params:
 * 	llist: linked list where to append the new node
 * 	data:  pointer to data of the new node
 * @returns;
 * 	0 on success
 * 	-1 on failure
 * 		- the only reason for failure is that there
 * 		is not enough memory to allocate a llist struct
 */
int llist_append(struct llist *llist, void *data);

/*
 * Get a llist node by index
 *
 * @params:
 * 	llist: linked list
 * 	idx: index of node
 * @returns:
 * 	pointer to llist or NULL
 */
struct llist *llist_get_by_idx(struct llist *llist, int idx);

/*
 * Remove node of linked list by index
 *
 * @params:
 * 	llist: pointer to linked list where node is to remove
 * 	idx: index of node to remove
 * 		- first node has index 0
 * 		- if idx is less than 0, the last node gets removed
 * 	data: the pointer to the data from the removed node gets stored here
 * @returns:
 * 	pointer to new linked list head
 */
struct llist *llist_rem_by_idx(struct llist *llist, int idx, void **data);

/*
 * Traverse the linked list and call data_trav for every node
 *
 * @params:
 * 	llist: pointer to linked list where node is to remove
 *  data_func_ctx: context information for data_trav
 * 	data_trav: function to call on every node
 * @returns:
 * 	-
 */
void llist_traverse(struct llist *llist, void *data_func_ctx, llist_data_func_t data_trav);

/*
 * Search the linked list. Search stops when data_search returns non-zero value
 *
 * @params:
 * 	llist: pointer to linked list
 *  data_func_ctx: context information for data_search
 * 	data_search: function to call on every node
 * 	res: (optional) address of pointer where search result gets stored. ignored if NULL
 * @returns:
 *  0: not found
 *  1: found (data is stored in **res (if not NULL))
 */
int llist_search(struct llist *llist, void *data_func_ctx, llist_data_func_t data_search, void **res);

#endif /* __LLIST__ */
