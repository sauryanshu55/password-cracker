#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void *thread_fn(void *arg) {
  char *message = (char *)arg;

  printf("Thread message: %s\n", message);

  return NULL;
}

int main(int argc, char **argv) {
  printf("Hello, world!\n");

  pthread_t threads[4];
  char *messages[4] = {"greetings", "potato", "fall break", "Wednesday"};

  for (int i = 0; i < 4; i++) {
    if (pthread_create(&threads[i], NULL, thread_fn, messages[i])) {
      perror("pthread_create failed");
      exit(EXIT_FAILURE);
    }
  }

  printf("Here.\n");

  for (int i = 0; i < 4; i++) {
    if (pthread_join(threads[i], NULL)) {
      perror("pthread_join failed");
      exit(EXIT_FAILURE);
    }
  }

  printf("Goodbye\n");

  return 0;
}
