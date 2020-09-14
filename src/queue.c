#include <stdlib.h>
#include "queue.h"

struct queue_node {
	void *data;
	struct queue_node *next;
};

/*
 * Create a new queue node
 */
static struct queue_node *queue_node_init(void *data);

/*
 * Destroy a queue node
 */
static void queue_node_destroy(struct queue_node *node);


struct queue *
queue_init(const unsigned int max_size)
{
	struct queue *queue = (struct queue *) malloc(sizeof(*queue));

	if (queue) {
		queue->max_size = max_size;
		queue->size = 0;
		queue->head = queue->tail = NULL;

		return queue;
	}
	return NULL;
}

void
queue_destroy(struct queue *queue, void *data_func_ctx, queue_data_func_t data_dtor)
{
	struct queue_node *node = queue->head;
	struct queue_node **node_next = &node->next;

	while (node != NULL) {
		if (data_dtor != NULL) {
			data_dtor(data_func_ctx, node->data);
		}
		free(node);
		node = *node_next;
		node_next = &node->next;
	}
}

int
queue_enqueue(struct queue *queue, void *data)
{
	struct queue_node *node;

	if (queue->max_size > 0 && queue->size == queue->max_size) {
		return QUEUE_EQFULL;
	}

	node = queue_node_init(data);
	if (!node) {
		return QUEUE_ENOMEM;
	}
	if (queue->size > 0) {
		queue->tail->next = node;
	} else {
		queue->head = node;
	}
	queue->tail = node;
	queue->size++;

	return QUEUE_ENOERR;
}

#include <stdio.h>

void *
queue_dequeue(struct queue *queue)
{
	struct queue_node *node;
	void *data;

	if (queue->size == 0) {
		return NULL;
	}
	node = queue->head;
	queue->head = queue->head->next;
	queue->size--;

	data = node->data;
	queue_node_destroy(node);

	return data;
}

int
queue_empty(struct queue *queue)
{
	return (queue->size == 0);
}

/*****************************/
/*          Private          */
/*****************************/

static
struct queue_node *
queue_node_init(void *data)
{
	struct queue_node *node = (struct queue_node *) malloc(sizeof(*node));
	
	if (node) {
		node->data = data;
		node->next = NULL;

		return node;
	}
	return NULL;
}

static
void
queue_node_destroy(struct queue_node *node)
{
	free(node);
}
