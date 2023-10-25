#define _GNU_SOURCE
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// /**
//  * Adaptation of djb2 hash function by Dan Berstein
//  * http://www.cse.yorku.ca/~oz/hash.html
//  *
//  * @param str String to be hashed
//  * @return unsigned long
//  */
// unsigned long hash(uint8_t *str) {
//   unsigned long hash = 5381;
//   int c;

//   while (c = *str++) {
//     hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
//   }

//   return hash;
// }

// typedef struct hash_table {
//   char **arr;
//   int size;
// } hash_table_t;

#define CHAR_IDX_OFFSET 87
#define MD5_HASH_LENGTH 32

int char_to_idx(char c) {
  if (isdigit(c)) {
    return (int)c;
  }

  return (int)c - CHAR_IDX_OFFSET;
}

typedef struct trie_node {
  struct trie_node *paths[MD5_HASH_LENGTH];
  const char *data;
} trie_node_t;

void insert(trie_node_t *trie, uint8_t *key, const char *val) {
  trie_node_t *cur_trie = trie;

  // Traverse tree till leaf
  for (int i = 0; i < MD5_HASH_LENGTH; i++) {
    int idx = char_to_idx(key[i]);
    if (cur_trie->paths[idx] == NULL) {
      cur_trie->paths[idx] = malloc(sizeof(trie_node_t));
    }
    cur_trie = cur_trie->paths[idx];
  }

  // Add data to leaf
  cur_trie->data = val;
}

const char *find(trie_node_t *trie, uint8_t *key) {
  trie_node_t *cur_trie = trie;

  for (int i = 0; i < MD5_HASH_LENGTH; i++) {
    int idx = char_to_idx(key[i]);
    cur_trie = cur_trie->paths[idx];
  }

  return cur_trie->data;
}

int main(int argc, char *argv[]) {
  uint8_t test = '7';
  if (isdigit(test)) {
    printf("DIGIT: %d\n", test);
  } else {
    printf("LETTER: %d\n", test);
  }
}