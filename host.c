        #define _GNU_SOURCE
	   #include <ctype.h>
       #include <errno.h>
       #include <pthread.h>
       #include <stdio.h>
       #include <stdlib.h>
       #include <string.h>
       #include <sys/types.h>
       #include <unistd.h>

       #define handle_error_en(en, msg) \
               do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

       #define handle_error(msg) \
               do { perror(msg); exit(EXIT_FAILURE); } while (0)

       struct thread_info {    /* Used as argument to thread_start() */
           pthread_t thread_id;        /* ID returned by pthread_create() */
           int       thread_num;       /* Application-defined thread # */
       //    char     *argv_string;      /* From command-line argument */
       };

       /* Thread start function: display address near top of our stack,
          and return upper-cased copy of argv_string. */

       static void *
       thread_start(void *arg)
       {
           struct thread_info *tinfo = arg;
           char *uargv;
			while(1)
			{
          	 printf("Thread %d: thread_id=%d,tid=%d,top of stack near %p; \n",
                  tinfo->thread_num, tinfo->thread_id,gettid(),(void *) &tinfo);
				  sleep(1);
			int i,j=0;
			for (int i = 0; i < 500000000; i++) j += 8;
			}

          

           return uargv;
       }

       int
       main(int argc, char *argv[])
       {
           int                 s, opt;
           void                *res;
           size_t              num_threads;
           ssize_t             stack_size;
           pthread_attr_t      attr;
           struct thread_info  *tinfo;

           /* The "-s" option specifies a stack size for our threads. */

           stack_size = -1;
           

           num_threads = 10;

           /* Initialize thread creation attributes. */

           s = pthread_attr_init(&attr);
           if (s != 0)
               handle_error_en(s, "pthread_attr_init");

           if (stack_size > 0) {
               s = pthread_attr_setstacksize(&attr, stack_size);
               if (s != 0)
                   handle_error_en(s, "pthread_attr_setstacksize");
           }

           /* Allocate memory for pthread_create() arguments. */

           tinfo = calloc(num_threads, sizeof(*tinfo));
           if (tinfo == NULL)
               handle_error("calloc");

           /* Create one thread for each command-line argument. */

           for (size_t tnum = 0; tnum < num_threads; tnum++) {
               tinfo[tnum].thread_num = tnum + 1;
               

               /* The pthread_create() call stores the thread ID into
                  corresponding element of tinfo[]. */

               s = pthread_create(&tinfo[tnum].thread_id, NULL,
                                  &thread_start, &tinfo[tnum]);
               if (s != 0)
                   handle_error_en(s, "pthread_create");
				
           }

           /* Destroy the thread attributes object, since it is no
              longer needed. */

           s = pthread_attr_destroy(&attr);
           if (s != 0)
               handle_error_en(s, "pthread_attr_destroy");

           /* Now join with each thread, and display its returned value. */
		   while(1)
		   {
			 printf("I am a host tid=%d (Hopefully I'm not infected)\n",gettid());
			 sleep(1);
			int i,j=0;
			for (int i = 0; i < 500000000; i++) j += 8;
		   }

           for (size_t tnum = 0; tnum < num_threads; tnum++) {
               s = pthread_join(tinfo[tnum].thread_id, &res);
               if (s != 0)
                   handle_error_en(s, "pthread_join");

               printf("Joined with thread %d; returned value was %s\n",
                      tinfo[tnum].thread_num, (char *) res);
               free(res);      /* Free memory allocated by thread */
           }

           free(tinfo);
           exit(EXIT_SUCCESS);
       }