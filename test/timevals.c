#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <sys/time.h>

static time_t time_t_max() {
	time_t max;
	#if defined(TIME_T_MAX)
		max = TIME_T_MAX;
	#else
		/* assume time_t to be an integer type */
		if ((time_t)-1 < (time_t)0) {
			if (sizeof (time_t) == sizeof (int)) {
				max = (time_t)INT_MAX;
			} else {
				assert(sizeof (time_t) == sizeof (long));
				max = (time_t)LONG_MAX;
			}
		} else {
			max = ~((time_t)0);
		}
	#endif
	return max;
}

static time_t time_t_min() {
	time_t min;
	#if defined(TIME_T_MIN)
		min = TIME_T_MIN;
	#else
		/* assume time_t to be an integer type */
		if ((time_t)-1 < (time_t)0) {
			if (sizeof (time_t) == sizeof (int)) {
				min = (time_t)INT_MIN;
			} else {
				assert(sizeof (time_t) == sizeof (long));
				min = (time_t)LONG_MIN;
			}
		} else {
			min = (time_t)0;
		}
	#endif
	return min;
}

static int timeval_cmp(struct timeval x, struct timeval y) {
	int r;
	if (x.tv_sec < y.tv_sec) {
		r = -1;
	} else if (x.tv_sec > y.tv_sec) {
		r = 1;
	} else if (x.tv_usec < y.tv_usec) {
		r = -1;
	} else if (x.tv_usec > y.tv_usec) {
		r = 1;
	} else {
		r = 0;
	}
	return r;
}

static struct timeval timeval_diff(struct timeval x, struct timeval y) {
	struct timeval r;
	assert((0 <= x.tv_usec) && (x.tv_usec < 1000000));
	assert((0 <= y.tv_usec) && (y.tv_usec < 1000000));
	if (x.tv_usec < y.tv_usec) {
		r.tv_usec = 1000000 - (y.tv_usec - x.tv_usec);
		r.tv_sec = x.tv_sec - y.tv_sec - 1;
	} else {
		r.tv_usec = x.tv_usec - y.tv_usec;
		r.tv_sec = x.tv_sec - y.tv_sec;
	}
	return r;
}

static int timeval_after_deadline(
	struct timeval t1, struct timeval t0, struct timeval dt)
{
	struct timeval d;
	assert((0 <= dt.tv_sec) && (0 <= dt.tv_usec) && (dt.tv_usec < 1000000));
	d = timeval_diff(t1, t0);
	return (d.tv_sec < 0) || (timeval_cmp(d, dt) > 0);
}

int main() {
	/* t1 = (struct timeval){LONG_MIN, 0} */

	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}));


	/* t1 = (struct timeval){LONG_MIN, 1} */

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX -1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}));


	/* t1 = (struct timeval){LONG_MIN + 1, 0} */

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}));


	/* t1 = (struct timeval){-1, 0} */

	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 0}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}));


	/* t1 = (struct timeval){-1, 999999} */

	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 999999}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 999999}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 999999}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}));


	/* t1 = (struct timeval){0, 0} */

	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 999999}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}));

	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 0}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}));


	/* t1 = (struct timeval){0, 1} */

	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 999999}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 999999}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 0}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 1}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 1}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 1}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}));


	/* t1 = (struct timeval){1, 0} */

	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 999999}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 1}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 1}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){1, 0}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){1, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}));


	/* t1 = (struct timeval){LONG_MAX - 1, 0} */

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}));


	/* t1 = (struct timeval){LONG_MAX, 0} */

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}));


	/* t1 = (struct timeval){LONG_MAX, 999999} */

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MIN + 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 999999}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 999999}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 999999}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){-1, 999999}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}, (struct timeval){LONG_MAX - 1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}, (struct timeval){1, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){0, 1}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 0}));
	assert(timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}, (struct timeval){LONG_MAX, 999999}));

	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){0, 1}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX - 1, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 0}));
	assert(!timeval_after_deadline(
		(struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}, (struct timeval){LONG_MAX, 999999}));

	int enabled = 0;
	assert(enabled = 1);
	if (enabled) {
		printf("DONE\n");
	}
	return 0;
}

/*
gcc -Wall -Wextra timevals.c
*/
