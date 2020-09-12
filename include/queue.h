#ifndef __QUEUE_H__
#define __QUEUE_H__

#define ENOERR	0
#define EQFULL	1
#define ENOMEM	2

typedef void (*queue_data_func_t) (void *data_func_ctx, void *data);

struct queue {
	unsigned int max_size;
	unsigned int size;
	struct queue_node *head;
	struct queue_node *tail;
};

/*
 * Create a new queue object
 * @params:
 * 	- max_size: if set to 0 there is no maximum size
 */
struct queue *queue_init(const unsigned int max_size); 

/*
 * Destroy an existing queue object
 * 
 */
void queue_destroy(struct queue *queue, void *data_func_ctx, queue_data_func_t data_dtor);

/*
 * Add queue node to queue
 */
int queue_enqueue(struct queue *queue, void *data);

/*
 * Get next node from queue
 */
void *queue_dequeue(struct queue *queue);

/*
 * Check if queue is empty
 * non-zero value means true
 */
int queue_empty(struct queue *queue);

#endif /* __QUEUE_H__ */
