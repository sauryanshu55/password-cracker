#define _GNU_SOURCE
#include <ctype.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERNAME_LENGTH 64
#define PASSWORD_LENGTH 6

#define ASCII_LOWERCASE_A 97
#define ASCII_LOWERCASE_Z 122

#define NUM_THREADS 4

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

    // Now check if the hash of the candidate password matches the input hash
    if (memcmp(input_hash, candidate_hash, MD5_DIGEST_LENGTH) == 0) {
      // Match! Copy the password to the output and return 0 (success)
      strncpy(output, password, PASSWORD_LENGTH + 1);
      return 0;
    } else {
      // No match. Return -1 (failure)
      return -1;
    }
  }

  // Recursive case: Try all letters for next position of password
  for (int ascii = ASCII_LOWERCASE_A; ascii <= ASCII_LOWERCASE_Z; ascii++) {
    // Append current letter to password
    password[PASSWORD_LENGTH - length] = (char)ascii;

    // Recursive call. Returns 0 if there is a match, -1 if there is not for the
    // passowrd provided as input
    int cracked =
        try_crack_single_password(input_hash, output, length - 1, password);

    if (cracked == 0) {
      return cracked; // Hashes match. Exit recursion prematurely!
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
#define DIGIT_IDX_OFFSET 48    // Unicode of '0'
#define LETTER_IDX_OFFSET 87   // Unicoode of 'a'
#define MD5_STRING_LENGTH 32   // Length of an MD5 string
#define MD5_NUM_CHARS (26 + 9) // Number of possible characters in an MD5 string

/**
 * A struct of a Trie node
 */
typedef struct trie_node {
  // An array of paths that are trie nodes
  struct trie_node *paths[MD5_NUM_CHARS];

  // Data contained at this node
  char *data;

} trie_node_t;

/**
 * Maps a character to an index in an
 * representing paths in a trie
 *
 * @param c Character to convert
 * @return int Index in an array of trie paths
 */
int char_to_idx(char c) {
  return c - (isdigit(c) ? DIGIT_IDX_OFFSET : LETTER_IDX_OFFSET);
}

/**
 * Initializes a trie node
 * Complete this implementation for part B of the lab.
 *
 * \param passwords  A pointer to allocated memory that will hold a password set
 */
void create(trie_node_t **trie) {
  *trie = malloc(sizeof(trie_node_t));
  for (int i = 0; i < MD5_NUM_CHARS; i++) {
    (*trie)->paths[i] = NULL;
  }
  (*trie)->data = NULL;
}

/**
 * Inserts a value into a path in a trie
 * determined by following the key
 *
 * @param trie Trie to insert into
 * @param key Key that signifies path to follow in trie
 * @param val Value to be inserted at end of path
 */
void insert(trie_node_t *trie, char *key, char *val) {
  trie_node_t *cur_trie = trie;

  // Traverse tree till leaf
  for (int i = 0; i < MD5_STRING_LENGTH; i++) {

    // Determine path to follow
    int path = char_to_idx(key[i]);

    // Allocate space if needed
    if (cur_trie->paths[path] == NULL) {
      create(&cur_trie->paths[path]);
    }

    // Follow path
    cur_trie = cur_trie->paths[path];
  }

  // Add data to leaf
  cur_trie->data = malloc(strlen(val));
  cur_trie->data = strdup(val);
}

bool find(trie_node_t *trie, char *key) {
  trie_node_t *cur_trie = trie;

  for (int i = 0; i < MD5_STRING_LENGTH; i++) {
    // Determine path to follow
    int path = char_to_idx(key[i]);

    // Terminate if no data is found
    if (cur_trie->paths[path] == NULL)
      return false;

    // Follow path
    cur_trie = cur_trie->paths[path];
  }

  // Print data when at leaf node
  printf("%s ", cur_trie->data);
  return true;
}

/**
 * Frees the fields of a password_set_t struct
 *
 * @param passwords Struct to free
 */

void destroy(trie_node_t *passwords) {
  // LATER
}

/**
 * Struct containing arguments passed to a thread
 */
typedef struct thread_arg {
  int start;              // The starting ASCII character
  int stop;               // The ending ASCII character
  int num_cracked;        // Stores the number of passwords cracked
  trie_node_t *passwords; // Pointer to the set of passwords to crack
} thread_arg_t;

// Total number of passwords to crack
int num_passwords = 0;

/**
 * Add a password to a password set
 * Complete this implementation for part B of the lab.
 *
 * \param passwords A pointer to a password set initialized
 *                  with the function above.
 * \param username  The name of the user being added.
 *                  The memory that holds this string's characters will be
 *                  reused, so if you keep a copy you must duplicate the string.
 *                  I recommend calling strdup().
 * \param password_hash  An array of MD5_DIGEST_LENGTH bytes
 *                       that holds the hash of this user's password.
 *                       The memory that holds this array will be reused, so you
 *                       must make a copy of this value if you retain it in
 *                        your data structure.
 */
void add_password(trie_node_t *passwords, char *username, char *password_hash) {
  // Allocate space for username and hash
  char *user = malloc(sizeof(char) * strlen(username));
  char *hash = malloc(sizeof(char) * MD5_STRING_LENGTH);

  // Create copies
  user = strdup(username);
  hash = strdup(password_hash);

  // Insert into trie
  insert(passwords, hash, user);

  // Increment password count
  num_passwords += 1;
}

/**
 * Attempt to find and crack a password
 * from a list of passwords
 *
 * @param passwords_set Set of usernames and passwords
 * @param length Length of the current `password`
 * @param password The candidate password to match
 * @return The number of passwords cracked
 */
int rec_crack_password(trie_node_t *passwords, int length, char password[]) {

  // Base Case: Password is at desired length. Try it!
  if (length == 0) {
    // This will hold the hash of the candidate password
    uint8_t candidate_hash[MD5_DIGEST_LENGTH];

    // Do the hash
    MD5((unsigned char *)password, PASSWORD_LENGTH, candidate_hash);

    // Get string representation of MD5
    char md5_string[MD5_STRING_LENGTH + 1];
    for (int i = 0; i < 16; ++i)
      sprintf(&md5_string[i * 2], "%02x", (unsigned int)candidate_hash[i]);

    // Now check if the password set contains the hash of the candidate
    // password
    if (find(passwords, md5_string)) {
      // Match! Print the username and cracked password
      // Return 1 because we cracked 1 password
      printf("%s\n", password);
      return 1;
    }

    // No match found. Return 0 because we cracked 0 passwords
    return 0;
  }

  // Try all letters for next position of password
  int num_cracked = 0;
  for (int ascii = ASCII_LOWERCASE_A; ascii <= ASCII_LOWERCASE_Z; ascii++) {
    // Append current letter to password
    password[PASSWORD_LENGTH - length] = (char)ascii;

    // Recursive call. Track the number of cracked passwords
    num_cracked += rec_crack_password(passwords, length - 1, password);
  }

  // Return the number of passwords cracked
  return num_cracked;
}

void *crack_password_worker(void *_args) {
  // Buffer to store password. Null-terminated.
  char password_candidate[PASSWORD_LENGTH + 1];
  password_candidate[PASSWORD_LENGTH] = '\0';

  // Cast argument to usable struct
  thread_arg_t *args = (thread_arg_t *)_args;

  // Generate all permutations in this search space
  for (int ascii = args->start; ascii <= args->stop; ascii++) {
    // Generate permutations starting with `ascii`
    password_candidate[0] = ascii;
    args->num_cracked += rec_crack_password(
        args->passwords, PASSWORD_LENGTH - 1, password_candidate);
  }

  // Exit thread when done
  pthread_exit(NULL);
}

/**
 * Crack all of the passwords in a set of passwords. The function should
 * print the username and cracked password for each user listed in
 * passwords, separated by a space character. Complete this implementation
 * for part B of
 *
 * TODO: More comments
 *
 * \returns The number of passwords cracked in the list
 */
int crack_password_list(trie_node_t *passwords) {
  // Divide the search space into 4 equal portions, as follows
  // Thread 1: A B C D E F
  // Thread 2: G H I J K L
  // Thread 3: M N O P Q R S
  // Thread 4: T U V W X Y Z
  int search_start[] = {'a', 'g', 'm', 't'};
  int search_stop[] = {'f', 'l', 's', 'z'};

  // Create threads
  pthread_t threads[NUM_THREADS];
  thread_arg_t args[NUM_THREADS];

  // Set arguments to pass to thread
  for (int i = 0; i < NUM_THREADS; i++) {
    args[i].start = search_start[i];
    args[i].stop = search_stop[i];
    args[i].num_cracked = 0;
    args[i].passwords = passwords;

    if (pthread_create(&threads[i], NULL, crack_password_worker, &args[i])) {
      perror("pthread create failed");
      exit(EXIT_FAILURE);
    }
  }

  // Join threads. Count the number of cracked passwords
  int total_cracked = 0;
  for (int i = 0; i < NUM_THREADS; i++) {
    if (pthread_join(threads[i], NULL)) {
      perror("pthread join failed");
      exit(EXIT_FAILURE);
    }

    // Aggregate number of cracked passwords
    total_cracked += args[i].num_cracked;
  }

  // Free password set
  destroy(passwords);

  // Return the number of passwords cracked
  return total_cracked;
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
    create(&passwords);

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
      // uint8_t password_hash[MD5_DIGEST_LENGTH];

      // Try to read. The space in the format string is required to eat the
      // newline
      if (fscanf(password_file, "%s %s ", username, md5_string) != 2) {
        fprintf(stderr, "Error reading password file: malformed line\n");
        exit(2);
      }

      // // Convert the MD5 string to MD5 bytes in our new node
      // if (md5_string_to_bytes(md5_string, password_hash) != 0) {
      //   fprintf(stderr, "Error reading MD5\n");
      //   exit(2);
      // }

      // Add the password to the password set
      add_password(passwords, username, md5_string);
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
