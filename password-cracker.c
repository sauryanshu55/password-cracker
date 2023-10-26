#define _GNU_SOURCE
#include <math.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERNAME_LENGTH 64
#define PASSWORD_LENGTH 6

#define NUM_THREADS 4

#define NUM_ENG_LETTERS 26
#define ASCII_LOWER_A 97
#define ASCII_LOWER_Z 122
#define NUM_UNSIGNED_CHARS 256

/************************* Part A *************************/

/**
 * Attempt to crack a single password
 *
 * @param input_hash The hashed password to be cracked
 * @param length Length of the current `password`
 * @param password The candidate password to match
 * @return int 0 if the password was cracked, -1 otherwise
 */
int try_crack_single_password(uint8_t *input_hash, char *output, int length,
                              char password[]) {

  // Base Case: Password is at desired length. Try it!
  if (length == 0) {
    // This will hold the hash of the candidate password
    uint8_t candidate_hash[MD5_DIGEST_LENGTH];

    // Do the hash
    MD5((unsigned char *)password, PASSWORD_LENGTH, candidate_hash);

    // Check if the hash of the candidate password matches the input hash
    if (memcmp(input_hash, candidate_hash, MD5_DIGEST_LENGTH) == 0) {
      // Match! Copy to output and return 1 (success)
      strncpy(output, password, PASSWORD_LENGTH + 1);
      return 0;
    } else {
      // No match. Return -1 (failure)
      return -1;
    }
  }

  // Recursive case: Try all letters for next position of password
  for (int ascii = ASCII_LOWER_A; ascii <= ASCII_LOWER_Z; ascii++) {
    // Append current letter to password
    password[PASSWORD_LENGTH - length] = (char)ascii;

    // Recursive call
    int cracked =
        try_crack_single_password(input_hash, output, length - 1, password);

    // Terminate if cracked password
    if (cracked == 0) {
      return cracked;
    }
  }

  return -1;
}

/**
 * Find a six character lower-case alphabetic password that hashes
 * to the given hash value. Complete this function for part A of the lab.
 * \param input_hash  An array of MD5_DIGEST_LENGTH bytes that
 *                    holds the hash of a password
 * \param output A pointer to memory with space for a six
 *               character password + '\0'
 * \returns 0 if the password was cracked. -1 otherwise.
 */
int crack_single_password(uint8_t *input_hash, char *output) {
  // Null-terminated buffer to store password
  char password_candidate[PASSWORD_LENGTH + 1];
  password_candidate[PASSWORD_LENGTH] = '\0';

  // Recursively try out all possible permutations of letters
  int cracked = try_crack_single_password(input_hash, output, PASSWORD_LENGTH,
                                          password_candidate);

  return cracked;
}

/********************* Parts B & C ************************/

// Total number of passwords to crack
int count_passwords = 0;

// Number of passwords already cracked
// This resource is shared across threads, hence the lock
pthread_mutex_t count_lock = PTHREAD_MUTEX_INITIALIZER;
int count_cracked = 0;

// Size of a search space
int size_search_space;

/**
 * Struct of a Trie node
 * \field paths An array of paths that are trie nodes
 * \field data Data contained at this node
 */
typedef struct trie_node {
  struct trie_node *paths[NUM_UNSIGNED_CHARS];
  int has_path[NUM_UNSIGNED_CHARS];
  char data[MAX_USERNAME_LENGTH];
} trie_node_t;

/**
 * Struct of arguments to pass to a thread
 * \field start The permutation to start searching
 * \field passwords Pointer to the set of passwords to crack
 */
typedef struct thread_arg {
  char start[PASSWORD_LENGTH];
  trie_node_t *passwords;
} thread_arg_t;

/**
 * Inserts a value into a path in a trie
 * determined by following the key
 *
 * @param trie Trie to insert into
 * @param key Key that signifies path to follow in trie
 * @param val Value to be inserted at end of path
 */
void insert(trie_node_t *trie, uint8_t *key, char *val) {
  trie_node_t *cur_trie = trie;

  // Traverse tree till leaf
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    // Determine path to follow
    int path = key[i];

    // Allocate space if needed
    if (cur_trie->has_path[path] == 0) {
      cur_trie->has_path[path] = 1;
      cur_trie->paths[path] = malloc(sizeof(trie_node_t));
    }

    // Follow path
    cur_trie = cur_trie->paths[path];
  }

  // Add data to leaf
  memcpy(cur_trie->data, val, strlen(val));
  cur_trie->data[strlen(val)] = '\0';
}

/**
 * Finds the value associated with a key in the trie
 *
 * @param trie A trie to search
 * @param key The key to search for
 * @return int Whether a value is found (1) or not (0)
 */
int find(trie_node_t *trie, uint8_t *key) {
  trie_node_t *cur_trie = trie;

  // Traverse tree
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    // Determine path to follow
    int path = key[i];

    // Terminate if no data is found
    if (cur_trie->has_path[path] == 0) {
      return 0;
    }

    // Follow path
    cur_trie = cur_trie->paths[path];
  }

  // At leaf node. Print data
  printf("%s ", cur_trie->data);
  return 1;
}

/**
 * Adds a password to a password set
 *
 * \param passwords A pointer to a trie containing passwords
 * \param username The name of the user being added
 * \param password_hash Array of bytes holding user's hashed password
 */
void add_password(trie_node_t *passwords, char *username,
                  uint8_t *password_hash) {
  // Insert into trie
  insert(passwords, password_hash, username);

  // Increment password count
  count_passwords += 1;
}

/**
 * @return int The size of a search space for a thread
 * This should be always be 77,228,944
 */
int get_size_search_space() {
  return (int)pow(NUM_ENG_LETTERS, PASSWORD_LENGTH) / NUM_THREADS;
}

/**
 * Gets the next string in the sequence
 * from "aaaaaa" to "zzzzzz"
 *
 * @param str The next string in sequence
 */
void increment(char str[]) {
  int idx = PASSWORD_LENGTH - 1;
  while (str[idx] == 'z') {
    str[idx] = 'a';
    idx--;
  }
  str[idx] += 1;
}

/**
 * Gets the search boundaries for all threads
 *
 * @param output Array to store output boundaries
 */
void generate_search_boundaries(char output[][PASSWORD_LENGTH]) {
  // First candidate
  char candidate[PASSWORD_LENGTH] = {'a', 'a', 'a', 'a', 'a', 'a'};

  // Each thread takes `size_search_space` candidates
  for (int i = 0; i < NUM_THREADS - 1; i++) {
    // Stores first candidate as boundary
    memcpy(output[i], candidate, PASSWORD_LENGTH);

    // Go to next boundary
    for (int j = 0; j < size_search_space; j++) {
      increment(candidate);
    }
  }

  // Last thread
  memcpy(output[NUM_THREADS - 1], candidate, PASSWORD_LENGTH);
}

/**
 * Function to be run by each thread to crack passwords
 * in its corresponding search space
 *
 * @param _args Arguments to the thread
 * @return void* Thread exits
 */
void *crack_password_worker(void *_args) {
  // Cast argument to usable struct
  thread_arg_t *args = (thread_arg_t *)_args;

  // This will hold the current candidate password
  char password[PASSWORD_LENGTH + 1];
  password[PASSWORD_LENGTH] = '\0';
  memcpy(password, args->start, PASSWORD_LENGTH);

  // This will hold the hash of the candidate password
  uint8_t candidate_hash[MD5_DIGEST_LENGTH];

  // Search and crack passwords
  for (int i = 0; i < size_search_space; i++) {
    // Terminate if all passwords have been cracked
    // We intentionally disregard the lock here
    if (count_cracked == count_passwords) {
      pthread_exit(NULL);
    }

    // Do the hash
    MD5((unsigned char *)password, PASSWORD_LENGTH, candidate_hash);

    // Check if the trie contains the hash of the candidate password
    if (find(args->passwords, candidate_hash)) {
      // Found! Print cracked password
      printf("%s\n", password);

      // Increment number of cracked passwords
      pthread_mutex_lock(&count_lock);
      count_cracked++;
      pthread_mutex_unlock(&count_lock);
    }

    // Go to next password
    increment(password);
  }

  // Exit thread when done
  pthread_exit(NULL);
}

/**
 * Cracks all of the passwords in a set of passwords.
 * Prints the username and cracked password for each user listed in
 * passwords, separated by a space character.
 *
 * \returns The number of passwords cracked in the list
 */
int crack_password_list(trie_node_t *passwords) {
  // Calculate search space size
  size_search_space = get_size_search_space();

  // Divide the search space into 4 exactly equal portions
  char search_boundaries[NUM_THREADS][PASSWORD_LENGTH];
  generate_search_boundaries(search_boundaries);

  // Threads and their arguments
  pthread_t threads[NUM_THREADS];
  thread_arg_t args[NUM_THREADS];

  // Set thread arguments and create threads
  for (int i = 0; i < NUM_THREADS; i++) {
    // Set arguments to pass to threads
    memcpy(args[i].start, search_boundaries[i], PASSWORD_LENGTH);
    args[i].passwords = passwords;

    if (pthread_create(&threads[i], NULL, crack_password_worker, &args[i])) {
      perror("pthread create failed");
      exit(EXIT_FAILURE);
    }
  }

  // Join threads
  for (int i = 0; i < NUM_THREADS; i++) {
    if (pthread_join(threads[i], NULL)) {
      perror("pthread join failed");
      exit(EXIT_FAILURE);
    }
  }

  // Return the number of passwords cracked
  return count_cracked;
}

/******************** Provided Code ***********************/

/**
 * Convert a string representation of an MD5 hash to a sequence
 * of bytes. The input md5_string must be 32 characters long, and
 * the output buffer bytes must have room for MD5_DIGEST_LENGTH
 * bytes.
 *
 * \param md5_string  The md5 string representation
 * \param bytes       The destination buffer for the converted md5 hash
 * \returns           0 on success, -1 otherwise
 */
int md5_string_to_bytes(const char *md5_string, uint8_t *bytes) {
  // Check for a valid MD5 string
  if (strlen(md5_string) != 2 * MD5_DIGEST_LENGTH)
    return -1;

  // Start our "cursor" at the start of the string
  const char *pos = md5_string;

  // Loop until we've read enough bytes
  for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++) {
    // Read one byte (two characters)
    int rc = sscanf(pos, "%2hhx", &bytes[i]);
    if (rc != 1)
      return -1;

    // Move the "cursor" to the next hexadecimal byte
    pos += 2;
  }

  return 0;
}

void print_usage(const char *exec_name) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s single <MD5 hash>\n", exec_name);
  fprintf(stderr, "  %s list <password file name>\n", exec_name);
}

int main(int argc, char **argv) {
  if (argc != 3) {
    print_usage(argv[0]);
    exit(1);
  }

  if (strcmp(argv[1], "single") == 0) {
    // The input MD5 hash is a string in hexadecimal. Convert it to bytes.
    uint8_t input_hash[MD5_DIGEST_LENGTH];
    if (md5_string_to_bytes(argv[2], input_hash)) {
      fprintf(stderr, "Input has value %s is not a valid MD5 hash.\n", argv[2]);
      exit(1);
    }

    // Now call the crack_single_password function
    char result[7];
    if (crack_single_password(input_hash, result)) {
      printf("No matching password found.\n");
    } else {
      printf("%s\n", result);
    }

  } else if (strcmp(argv[1], "list") == 0) {
    // Make and initialize a password set
    trie_node_t *passwords;
    passwords = malloc(sizeof(trie_node_t));

    // Open the password file
    FILE *password_file = fopen(argv[2], "r");
    if (password_file == NULL) {
      perror("opening password file");
      exit(2);
    }

    int password_count = 0;

    // Read until we hit the end of the file
    while (!feof(password_file)) {
      // Make space to hold the username
      char username[MAX_USERNAME_LENGTH];

      // Make space to hold the MD5 string
      char md5_string[MD5_DIGEST_LENGTH * 2 + 1];

      // Make space to hold the MD5 bytes
      uint8_t password_hash[MD5_DIGEST_LENGTH];

      // Try to read. The space in the format string is required to eat the
      // newline
      if (fscanf(password_file, "%s %s ", username, md5_string) != 2) {
        fprintf(stderr, "Error reading password file: malformed line\n");
        exit(2);
      }

      // Convert the MD5 string to MD5 bytes in our new node
      if (md5_string_to_bytes(md5_string, password_hash) != 0) {
        fprintf(stderr, "Error reading MD5\n");
        exit(2);
      }

      // Add the password to the password set
      add_password(passwords, username, password_hash);
      password_count++;
    }

    // Now run the password list cracker
    int cracked = crack_password_list(passwords);

    printf("Cracked %d of %d passwords.\n", cracked, password_count);

  } else {
    print_usage(argv[0]);
    exit(1);
  }

  return 0;
}
